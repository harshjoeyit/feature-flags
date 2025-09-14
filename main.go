package main

import (
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/posthog/posthog-go"
)

// PostHog configuration
const (
	DefaultPostHogHost = "https://app.posthog.com"
)

// FeatureFlag holds the flag state
// RolloutPercent 0-100 (0 disabled, 100 fully enabled)
type FeatureFlag struct {
	Name           string         `json:"name"`
	Enabled        bool           `json:"enabled"`
	RolloutPercent int            `json:"rollout_percent"`
	Variants       map[string]int `json:"variants"` // A/B testing variants with percentages
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// EvaluationRequest represents a feature flag evaluation request
type EvaluationRequest struct {
	FlagName   string            `json:"flag_name"`
	UserID     string            `json:"user_id"`
	Attributes map[string]string `json:"attributes"`
}

// EvaluationResponse represents the result of flag evaluation
type EvaluationResponse struct {
	Enabled   bool      `json:"enabled"`
	Variant   string    `json:"variant,omitempty"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// Metrics for monitoring
type Metrics struct {
	VariantCounts map[string]map[string]int64 `json:"variant_counts"`
	LastReset     time.Time                   `json:"last_reset"`
	mu            sync.RWMutex
}

// FeatureFlagService defines interface for feature evaluation
// This interface makes it easy to swap implementations (local, PostHog, etc.)
type FeatureFlagService interface {
	GetFlags() []*FeatureFlag
	CreateFlag(flag *FeatureFlag) error
	UpdateFlag(flagName string, updatedFlag *FeatureFlag) error
	EvaluateFlag(evalReq *EvaluationRequest) (*EvaluationResponse, error)
	GetMetrics() *Metrics
	Close() error // For cleanup if needed
}

// InMemoryFeatureFlagService implements FeatureFlagService (stores flags in memory)
// Simple percentage rollout based on userID hashing
type InMemoryFeatureFlagService struct {
	flags   map[string]*FeatureFlag
	metrics *Metrics
	mu      sync.RWMutex
}

func NewInMemoryFeatureFlagService() FeatureFlagService {
	return &InMemoryFeatureFlagService{
		flags: make(map[string]*FeatureFlag),
		metrics: &Metrics{
			VariantCounts: make(map[string]map[string]int64),
			LastReset:     time.Now(),
		},
	}
}

func (ffs *InMemoryFeatureFlagService) GetFlags() []*FeatureFlag {
	ffs.mu.RLock()
	defer ffs.mu.RUnlock()

	list := make([]*FeatureFlag, 0, len(ffs.flags))
	for _, f := range ffs.flags {
		list = append(list, f)
	}
	return list
}

func (ffs *InMemoryFeatureFlagService) CreateFlag(flag *FeatureFlag) error {
	ffs.mu.Lock()
	defer ffs.mu.Unlock()

	if _, exists := ffs.flags[flag.Name]; exists {
		return fmt.Errorf("flag %s already exists", flag.Name)
	}

	flag.CreatedAt = time.Now()
	flag.UpdatedAt = time.Now()
	ffs.flags[flag.Name] = flag

	// Initialize metrics
	ffs.metrics.mu.Lock()
	ffs.metrics.VariantCounts[flag.Name] = make(map[string]int64)
	ffs.metrics.mu.Unlock()

	return nil
}

// UpdateFlag updates an existing feature flag
func (ffs *InMemoryFeatureFlagService) UpdateFlag(flagName string, updatedFlag *FeatureFlag) error {
	ffs.mu.Lock()
	defer ffs.mu.Unlock()

	existing, exists := ffs.flags[flagName]
	if !exists {
		return fmt.Errorf("flag %s does not exist", flagName)
	}

	updatedFlag.Name = flagName // Ensure name remains unchanged
	updatedFlag.CreatedAt = existing.CreatedAt
	updatedFlag.UpdatedAt = time.Now()

	ffs.flags[flagName] = updatedFlag

	return nil
}

// EvaluateFlag evaluates a feature flag for a specific user
func (ffs *InMemoryFeatureFlagService) EvaluateFlag(req *EvaluationRequest) (*EvaluationResponse, error) {
	ffs.mu.RLock()
	flag, exists := ffs.flags[req.FlagName]
	ffs.mu.RUnlock()

	if !exists {
		return &EvaluationResponse{
			Enabled:   false,
			Reason:    "flag_not_found",
			Timestamp: time.Now(),
		}, nil
	}

	response := &EvaluationResponse{
		Timestamp: time.Now(),
	}

	// Check if flag is globally disabled
	if !flag.Enabled {
		response.Enabled = false
		response.Reason = "flag_disabled"
		return response, nil
	}

	// Check percentage rollout
	userHash := ffs.hashUser(req.UserID)
	if userHash <= flag.RolloutPercent {
		response.Enabled = true
		response.Reason = "rollout_percentage"

		// Select variant if A/B testing is configured
		if len(flag.Variants) > 0 {
			response.Variant = ffs.selectVariant(flag.Variants, req.UserID)
		}
	} else {
		response.Enabled = false
		response.Reason = "rollout_percentage"
	}

	ffs.updateVariantMetrics(req.FlagName, response.Variant)
	return response, nil
}

// selectVariant selects a variant based on percentage distribution
func (ffs *InMemoryFeatureFlagService) selectVariant(variants map[string]int, userID string) string {
	if len(variants) == 0 {
		return ""
	}

	// Sort variant names for consistent iteration order
	// to make sure the selection is deterministic
	// i.e. same user gets same variant every time.
	// This needs to be done because map iteration order is random in Go.
	var sortedVariants []string
	for variant := range variants {
		sortedVariants = append(sortedVariants, variant)
	}
	sort.Strings(sortedVariants)

	userHash := ffs.hashUser(userID + "_variant")
	cumulative := 0

	for _, variant := range sortedVariants {
		percentage := variants[variant]
		cumulative += percentage
		if userHash < cumulative {
			return variant
		}
	}

	return ""
}

func (ffs *InMemoryFeatureFlagService) Close() error {
	// No resources to clean up in this implementation
	return nil
}

// hashUser creates a deterministic hash for consistent rollout
func (ffs *InMemoryFeatureFlagService) hashUser(userID string) int {
	h := fnv.New32a()
	h.Write([]byte(userID))
	return int(h.Sum32() % 100)
}

// updateVariantMetrics updates variant usage metrics
func (ffs *InMemoryFeatureFlagService) updateVariantMetrics(flagName, variant string) {
	ffs.metrics.mu.Lock()
	defer ffs.metrics.mu.Unlock()

	if ffs.metrics.VariantCounts[flagName] == nil {
		ffs.metrics.VariantCounts[flagName] = make(map[string]int64)
	}

	if variant != "" {
		ffs.metrics.VariantCounts[flagName][variant]++
	} else {
		ffs.metrics.VariantCounts[flagName]["default"]++
	}
}

// GetMetrics returns current metrics
func (ffs *InMemoryFeatureFlagService) GetMetrics() *Metrics {
	ffs.metrics.mu.RLock()
	defer ffs.metrics.mu.RUnlock()

	// Create a deep copy to avoid race conditions
	metricsCopy := &Metrics{
		VariantCounts: make(map[string]map[string]int64),
		LastReset:     ffs.metrics.LastReset,
	}

	for flag, variants := range ffs.metrics.VariantCounts {
		metricsCopy.VariantCounts[flag] = make(map[string]int64)
		for variant, count := range variants {
			metricsCopy.VariantCounts[flag][variant] = count
		}
	}

	return metricsCopy
}

type PosthogFeatureFlagService struct {
	client posthog.Client
}

func NewPosthogFeatureFlagService(apiKey, host string) FeatureFlagService {
	client, _ := posthog.NewWithConfig(apiKey, posthog.Config{Endpoint: host})
	return &PosthogFeatureFlagService{
		client: client,
	}
}

func (pffs *PosthogFeatureFlagService) GetFlags() []*FeatureFlag {
	// Implement fetching flags from PostHog
	return []*FeatureFlag{}
}

func (pffs *PosthogFeatureFlagService) CreateFlag(flag *FeatureFlag) error {
	// Implement flag creation in PostHog
	return nil
}

func (pffs *PosthogFeatureFlagService) UpdateFlag(name string, flag *FeatureFlag) error {
	// Implement flag update in PostHog
	return nil
}

func (pffs *PosthogFeatureFlagService) EvaluateFlag(req *EvaluationRequest) (*EvaluationResponse, error) {
	// Implement flag evaluation using PostHog
	return &EvaluationResponse{
		Enabled:   false,
		Reason:    "not_implemented",
		Timestamp: time.Now(),
	}, nil
}

func (pffs *PosthogFeatureFlagService) GetMetrics() *Metrics {
	// Implement fetching metrics from PostHog if available
	return &Metrics{
		VariantCounts: make(map[string]map[string]int64),
		LastReset:     time.Now(),
	}
}

func (pffs *PosthogFeatureFlagService) Close() error {
	return pffs.client.Close()
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}

	postHogHostEndpoint := "https://eu.i.posthog.com"
	posthogAPIKey := os.Getenv("POSTHOG_API_KEY")
	if posthogAPIKey == "" {
		log.Fatal("POSTHOG_API_KEY environment variable is required")
	}

	ffs := NewPosthogFeatureFlagService(posthogAPIKey, postHogHostEndpoint)
	defer ffs.Close()

	ffs.GetFlags()
	ffs.CreateFlag(&FeatureFlag{
		Name:           "test_flag",
		Enabled:        true,
		RolloutPercent: 50,
		Variants: map[string]int{
			"variant_a": 50,
			"variant_b": 50,
		},
	})
	ffs.UpdateFlag("test_flag", &FeatureFlag{
		Name:           "test_flag",
		Enabled:        true,
		RolloutPercent: 75,
		Variants: map[string]int{
			"variant_a": 30,
			"variant_b": 70,
		},
	})
	ffs.EvaluateFlag(&EvaluationRequest{
		FlagName: "test_flag",
		UserID:   "user_123",
	})

	ge := gin.Default()

	// ffs := NewInMemoryFeatureFlagService()

	ge.GET("/flags", func(c *gin.Context) {
		flags := ffs.GetFlags()
		c.JSON(http.StatusOK, flags)
	})

	ge.POST("/flags", func(c *gin.Context) {
		var flag FeatureFlag
		if err := c.ShouldBindJSON(&flag); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
			return
		}
		if flag.Name == "" || flag.RolloutPercent < 0 || flag.RolloutPercent > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid flag attributes"})
			return
		}

		_ = ffs.CreateFlag(&flag)
		c.Status(http.StatusNoContent)
	})

	ge.PUT("/flags/:name", func(c *gin.Context) {
		name := c.Param("name")
		var flag FeatureFlag
		if err := c.ShouldBindJSON(&flag); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
			return
		}

		if flag.RolloutPercent < 0 || flag.RolloutPercent > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rollout percentage"})
			return
		}

		err := ffs.UpdateFlag(name, &flag)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	})

	ge.GET("/flags/evaluate", func(c *gin.Context) {
		userID := c.Query("userid")
		flagName := c.Query("flag")
		if flagName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing flag parameter"})
			return
		}

		evalReq := &EvaluationRequest{
			FlagName: flagName,
			UserID:   userID,
		}

		resp, err := ffs.EvaluateFlag(evalReq)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, resp)
	})

	ge.GET("/flags/metrics", func(c *gin.Context) {
		metrics := ffs.GetMetrics()
		c.JSON(http.StatusOK, metrics)
	})

	ge.Run(":9090")
}
