package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// FeatureFlag holds the flag state
// RolloutPercent 0-100 (0 disabled, 100 fully enabled)
type FeatureFlag struct {
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	RolloutPercent int    `json:"rollout_percent"`
}

// FeatureFlagClient defines interface for feature evaluation
// This interface makes it easy to swap implementations (local, PostHog, etc.)
type FeatureFlagClient interface {
	EvaluateFlag(flagName, userID string) bool
	GetFlags() []FeatureFlag
	CreateOrUpdateFlag(flag FeatureFlag) error
}

// InMemoryFlagClient implements FeatureFlagClient (stores flags in memory)
// Simple percentage rollout based on userID hashing
type InMemoryFlagClient struct {
	flags map[string]FeatureFlag
	mu    sync.RWMutex
}

func NewInMemoryFlagClient() *InMemoryFlagClient {
	return &InMemoryFlagClient{
		flags: make(map[string]FeatureFlag),
	}
}

func (c *InMemoryFlagClient) GetFlags() []FeatureFlag {
	c.mu.RLock()
	defer c.mu.RUnlock()

	list := make([]FeatureFlag, 0, len(c.flags))
	for _, f := range c.flags {
		list = append(list, f)
	}
	return list
}

func (c *InMemoryFlagClient) CreateOrUpdateFlag(flag FeatureFlag) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flags[strings.ToLower(flag.Name)] = flag
	return nil
}

func (c *InMemoryFlagClient) EvaluateFlag(flagName string, userID string) bool {
	fmt.Println("Evaluating flag:", flagName, "for user:", userID)
	if userID == "" {
		return false // No userID means no rollout
	}

	c.mu.RLock()
	flag, exists := c.flags[strings.ToLower(flagName)]
	c.mu.RUnlock()
	if !exists || !flag.Enabled || flag.RolloutPercent <= 0 {
		return false
	}

	// Hash userID + flagName to determine rollout segment
	h := sha256.Sum256([]byte(userID + flag.Name))
	hashVal := int(h[0]) // Use first byte (0-255)
	rolloutThreshold := flag.RolloutPercent * 255 / 100

	fmt.Printf("Evaluating flag '%s' for user '%s': hashVal=%d, threshold=%d\n", flagName, userID, hashVal, rolloutThreshold)

	return hashVal < rolloutThreshold
}

func main() {
	r := gin.Default()
	client := NewInMemoryFlagClient()

	r.GET("/flags", func(c *gin.Context) {
		flags := client.GetFlags()
		c.JSON(http.StatusOK, flags)
	})

	r.POST("/flags", func(c *gin.Context) {
		var flag FeatureFlag
		if err := c.ShouldBindJSON(&flag); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
			return
		}
		if flag.Name == "" || flag.RolloutPercent < 0 || flag.RolloutPercent > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid flag attributes"})
			return
		}
		_ = client.CreateOrUpdateFlag(flag)
		c.Status(http.StatusNoContent)
	})

	r.GET("/flags/evaluate", func(c *gin.Context) {
		flagName := c.Query("flag")
		userID := c.Query("userid")
		if flagName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing flag parameter"})
			return
		}
		enabled := client.EvaluateFlag(flagName, userID)
		c.JSON(http.StatusOK, gin.H{"enabled": enabled})
	})

	r.Run(":9090")
}
