# TSC Benchmarks

Add the tenant id and api key that you'd like to test with to the `IntegrationBenchmark`.

```
mvn clean install
java -Xms1024m -Xmx1024m -jar target/benchmarks.jar
```

You have to benchmark an actual version of the TSC, though this can be a `SNAPSHOT` version published locally.
Update the `pom.xml` to whatever version you'd like to test.
