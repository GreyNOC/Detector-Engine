rule SampleDemo : defensive
{
    meta:
        description = "Sample YARA rule for ingestion tests."
        author = "test"
        reference = "https://example.test/rule"
    strings:
        $a = "PLACEHOLDER_STRING_FOR_TEST"
    condition:
        $a
}
