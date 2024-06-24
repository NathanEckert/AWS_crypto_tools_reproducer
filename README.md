# AWS_crypto_tools_reproducer

Reproduce https://github.com/aws/amazon-s3-encryption-client-java/issues/300

## Steps to reproduce

Add a file named `AwsTestsSecrets` alongside `TestEndOfStreamBehavior`.

This file should contain the following:

```java
import software.amazon.awssdk.regions.Region;

public class AwsTestsSecrets {
  public static final String AWS_TEST_BUCKET = "your bucket here";

  public static final Region DEFAULT_REGION = "your region here";

  public static final String PUBLIC_KEY = "your public key here";
  public static final String PRIVATE_KEY = "your private key here";

}
```

Then run `TestEndOfStreamBehavior`, either through your IDE or through the command line (`mvn clean install`).

## Expected behavior

The reproducer should throw an exception when using the EncryptionClient, but not the regular client.