package claimbench

import "testing"

var (
	benchmarkBytesResult []byte
	benchmarkBoolResult  bool
	benchmarkNodesResult interface{}
)

func TestAuthorizationImplementationsAgree(t *testing.T) {
	if !isAuthorizedJSONPath(benchmarkClaims, benchmarkAssertions) {
		t.Fatal("JSONPath implementation rejected benchmark claims")
	}
	if !isAuthorizedDirect(benchmarkClaims, benchmarkAssertions) {
		t.Fatal("direct implementation rejected benchmark claims")
	}
}

func TestBenchmarkJWT(t *testing.T) {
	if err := prepareBenchmarkJWT(); err != nil {
		t.Fatal(err)
	}
	claims, err := validateBenchmarkJWT()
	if err != nil {
		t.Fatalf("JWT validation failed: %v", err)
	}
	if !isAuthorizedJSONPath(claims, benchmarkAssertions) {
		t.Fatal("JWT claims failed authorization")
	}
}

func BenchmarkMarshal(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var err error
		benchmarkBytesResult, err = marshalClaims(benchmarkClaims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSONPath(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		value, err := selectClaim(benchmarkClaims, "groups")
		if err != nil {
			b.Fatal(err)
		}
		benchmarkNodesResult = value
	}
}

func BenchmarkAuthorizationJSONPath(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkBoolResult = isAuthorizedJSONPath(benchmarkClaims, benchmarkAssertions)
	}
}

func BenchmarkAuthorizationDirect(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkBoolResult = isAuthorizedDirect(benchmarkClaims, benchmarkAssertions)
	}
}

func BenchmarkJWT(b *testing.B) {
	if err := prepareBenchmarkJWT(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validateBenchmarkJWT()
		benchmarkBoolResult = err == nil
	}
}

func BenchmarkJWTAndAuthorizationJSONPath(b *testing.B) {
	if err := prepareBenchmarkJWT(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		claims, err := validateBenchmarkJWT()
		benchmarkBoolResult = err == nil && isAuthorizedJSONPath(claims, benchmarkAssertions)
	}
}
