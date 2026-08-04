package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"
)

func main() {
	baseURL := flag.String("url", "http://127.0.0.1:18080", "Traefik benchmark base URL")
	requests := flag.Int("n", 5000, "measured requests per mode")
	warmup := flag.Int("warmup", 200, "warmup requests per mode")
	flag.Parse()

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     time.Minute,
		},
		Timeout: 10 * time.Second,
	}
	defer client.CloseIdleConnections()

	for _, mode := range []string{"baseline", "marshal", "jsonpath", "full", "direct", "jwt", "jwt-full"} {
		url := *baseURL + "/" + mode
		for i := 0; i < *warmup; i++ {
			if err := request(client, url); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}

		durations := make([]time.Duration, *requests)
		started := time.Now()
		for i := 0; i < *requests; i++ {
			requestStarted := time.Now()
			if err := request(client, url); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			durations[i] = time.Since(requestStarted)
		}
		elapsed := time.Since(started)

		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		fmt.Printf(
			"%-9s n=%d mean=%8.3f us p50=%8.3f us p95=%8.3f us p99=%8.3f us throughput=%8.1f req/s\n",
			mode,
			*requests,
			float64(elapsed.Microseconds())/float64(*requests),
			microseconds(percentile(durations, 0.50)),
			microseconds(percentile(durations, 0.95)),
			microseconds(percentile(durations, 0.99)),
			float64(*requests)/elapsed.Seconds(),
		)
	}
}

func request(client *http.Client, url string) error {
	response, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("GET %s: status %s", url, response.Status)
	}
	return nil
}

func percentile(values []time.Duration, quantile float64) time.Duration {
	index := int(float64(len(values)-1) * quantile)
	return values[index]
}

func microseconds(value time.Duration) float64 {
	return float64(value.Nanoseconds()) / 1000
}
