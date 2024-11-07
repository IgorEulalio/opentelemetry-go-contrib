// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package eks // import "go.opentelemetry.io/contrib/detectors/aws/eks"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const (
	k8sTokenPath          = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // False positive G101: Potential hardcoded credentials. The detector only check if the token exists.
	k8sCertPath           = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	authConfigmapNS       = "kube-system"
	authConfigmapName     = "aws-auth"
	cwConfigmapNS         = "amazon-cloudwatch"
	cwConfigmapName       = "cluster-info"
	defaultCgroupPath     = "/proc/self/cgroup"
	containerIDLength     = 64
	instanceIdMetadataKey = "instance-id"
)

// detectorUtils is used for testing the resourceDetector by abstracting functions that rely on external systems.
type detectorUtils interface {
	fileExists(filename string) bool
	getInstanceTags(ctx context.Context, instanceId string) ([]types.TagDescription, error)
	getInstanceId(ctx context.Context) (string, error)
	getConfigMap(ctx context.Context, namespace string, name string) (map[string]string, error)
	getContainerID() (string, error)
}

// This struct will implement the detectorUtils interface.
type eksDetectorUtils struct {
	clientset  *kubernetes.Clientset
	imdsClient *imds.Client
	ec2Client  *ec2.Client
}

// resourceDetector for detecting resources running on Amazon EKS.
type resourceDetector struct {
	utils detectorUtils
}

// Compile time assertion that resourceDetector implements the resource.Detector interface.
var _ resource.Detector = (*resourceDetector)(nil)

// Compile time assertion that eksDetectorUtils implements the detectorUtils interface.
var _ detectorUtils = (*eksDetectorUtils)(nil)

// NewResourceDetector returns a resource detector that will detect AWS EKS resources.
func NewResourceDetector() (resource.Detector, error) {
	utils, err := newK8sDetectorUtils()
	return &resourceDetector{utils: utils}, err
}

// Detect returns a Resource describing the Amazon EKS environment being run in.
// If the environment is not running in EKS, an empty Resource and nil error is returned.
// If the environment is running in EKS, a Resource with the following attributes is returned:
// - cloud.provider: aws
// - cloud.platform: aws-eks
// - k8s.cluster.name: <clusterName>
// - container.id: <containerID>
func (detector *resourceDetector) Detect(ctx context.Context) (*resource.Resource, error) {
	// Check if running in EKS
	isEks, err := isEKS(ctx, detector.utils)
	if err != nil {
		return nil, err
	}

	// Return empty resource object if not running in EKS
	if !isEks {
		return resource.Empty(), nil
	}

	// Create variable to hold resource attributes
	attributes := []attribute.KeyValue{
		semconv.CloudProviderAWS,
		semconv.CloudPlatformAWSEKS,
	}

	// Get clusterName and append to attributes
	clusterName, _ := getClusterName(ctx, detector.utils)
	if clusterName != "" {
		attributes = append(attributes, semconv.K8SClusterName(clusterName))
	}

	// Get containerID and append to attributes
	containerID, _ := detector.utils.getContainerID()
	if containerID != "" {
		attributes = append(attributes, semconv.ContainerID(containerID))
	}

	// Return new resource object with clusterName and containerID as attributes
	return resource.NewWithAttributes(semconv.SchemaURL, attributes...), nil
}

// isK8s checks if the current environment is running in a Kubernetes environment.
func isK8s(utils detectorUtils) bool {
	return utils.fileExists(k8sTokenPath) && utils.fileExists(k8sCertPath)
}

// fileExists checks if a file with a given filename exists.
func (eksUtils eksDetectorUtils) fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

// getConfigMap retrieves the configuration map from the k8s API.
func (eksUtils eksDetectorUtils) getConfigMap(ctx context.Context, namespace string, name string) (map[string]string, error) {
	cm, err := eksUtils.clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ConfigMap %s/%s: %w", namespace, name, err)
	}

	return cm.Data, nil
}

// getInstanceTags retrieves the instance tags trough the AWS EC2 API.
func (eksUtils eksDetectorUtils) getInstanceTags(ctx context.Context, instanceId string) ([]types.TagDescription, error) {
	tags, err := eksUtils.ec2Client.DescribeTags(ctx, &ec2.DescribeTagsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("resource-id"),
				Values: []string{instanceId},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return tags.Tags, nil
}

// getInstanceId retrieves the instance ID from the EC2 metadata service.
func (eksUtils eksDetectorUtils) getInstanceId(ctx context.Context) (string, error) {
	metadata, err := eksUtils.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{})
	if err != nil {
		return "", err
	}
	instanceID, ok := metadata.ResultMetadata.Get(instanceIdMetadataKey).(string)
	if !ok || instanceID == "" {
		return "", errors.New("instance ID not found")
	}
	return instanceID, nil
}

// getContainerID returns the containerID if currently running within a container.
func (eksUtils eksDetectorUtils) getContainerID() (string, error) {
	fileData, err := os.ReadFile(defaultCgroupPath)
	if err != nil {
		return "", fmt.Errorf("getContainerID() error: cannot read file with path %s: %w", defaultCgroupPath, err)
	}

	// is this going to stop working with 1.20 when Docker is deprecated?
	r, err := regexp.Compile(`^.*/docker/(.+)$`)
	if err != nil {
		return "", err
	}

	// Retrieve containerID from file
	splitData := strings.Split(strings.TrimSpace(string(fileData)), "\n")
	for _, str := range splitData {
		if r.MatchString(str) {
			return str[len(str)-containerIDLength:], nil
		}
	}
	return "", fmt.Errorf("getContainerID() error: cannot read containerID from file %s", defaultCgroupPath)
}

// getClusterName retrieves the clusterName resource attribute.
func getClusterName(ctx context.Context, utils detectorUtils) (string, error) {
	instanceId, err := utils.getInstanceId(ctx)
	if err != nil {
		return "", err
	}

	tags, err := utils.getInstanceTags(ctx, instanceId)
	if err != nil {
		return "", err
	}

	for _, tag := range tags {
		if *tag.Key == "eks:cluster-name" {
			return *tag.Value, nil
		}
	}

	return "", errors.New("eks:cluster-name tag not found")
}

// isEKS checks if the current environment is running in EKS.
func isEKS(ctx context.Context, utils detectorUtils) (bool, error) {
	if !isK8s(utils) {
		return false, nil
	}

	// Make HTTP GET request
	awsAuth, err := utils.getConfigMap(ctx, authConfigmapNS, authConfigmapName)
	if err != nil {
		return false, fmt.Errorf("isEks() error retrieving auth configmap: %w", err)
	}

	return awsAuth != nil, nil
}

// newK8sDetectorUtils creates the Kubernetes clientset.
func newK8sDetectorUtils() (*eksDetectorUtils, error) {
	// Get cluster configuration
	confs, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create config: %w", err)
	}

	// Create clientset using generated configuration
	clientset, err := kubernetes.NewForConfig(confs)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset for Kubernetes client")
	}

	// Create configuration for AWS client based on default credential chain
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS client")
	}

	return &eksDetectorUtils{
		clientset:  clientset,
		imdsClient: imds.NewFromConfig(cfg),
		ec2Client:  ec2.NewFromConfig(cfg),
	}, nil
}
