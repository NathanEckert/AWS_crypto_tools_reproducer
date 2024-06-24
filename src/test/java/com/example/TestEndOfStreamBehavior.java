
package com.example;

import static com.example.AwsTestsSecrets.PRIVATE_KEY;
import static com.example.AwsTestsSecrets.PUBLIC_KEY;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Stream;

import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.ParameterizedTest;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;


public class TestEndOfStreamBehavior {

	private static final String BUCKET = AwsTestsSecrets.AWS_TEST_BUCKET;
	private static final String KEY = "GHI-300.txt";
	private static final AwsCredentialsProvider CREDENTIALS = DefaultCredentialsProvider.create();

	private static final byte[] CONTENT = new String(new char[4])
			.replace("\0", "abcdefghijklmnopqrstuvwxyz0123456789")
			.getBytes();

	public static final KeyPair KEY_PAIR;

	static {
		KEY_PAIR = generateKeyPair(
				PUBLIC_KEY,
				PRIVATE_KEY);
	}

	static Stream<S3Client> clientProvider() {
		return Stream.of(
				getClient(AwsTestsSecrets.DEFAULT_REGION),
				getEncryptionClient(KEY_PAIR, AwsTestsSecrets.DEFAULT_REGION));
	}

	@ParameterizedTest
	@MethodSource("clientProvider")
	void testEndOfStreamBehavior(final S3Client client) throws Exception {
		// Delete the data if it exists
		final DeleteObjectRequest deleteRequest = DeleteObjectRequest.builder()
				.bucket(BUCKET)
				.key(KEY)
				.build();

		client.deleteObject(deleteRequest);

		// Upload the data
		final PutObjectRequest uploadRequest =
				PutObjectRequest.builder().bucket(BUCKET).key(KEY).build();
		client.putObject(uploadRequest, RequestBody.fromBytes(CONTENT));
		// wait 5 seconds for the data to be uploaded
		Thread.sleep(5000);

		// Actual test
		final GetObjectRequest downloadRequest =
				GetObjectRequest.builder()
						.bucket(BUCKET)
						.key(KEY)
						.range("bytes=0-15")
						.build();

		final InputStream stream = client.getObject(downloadRequest);

		// Buffer capacity matters !!!
		// Behavior difference when the capacity is same as the content length (i.e. 16) of the ranged query
		final ByteBuffer buffer = ByteBuffer.allocate(16);
		final byte[] underlyingBuffer = buffer.array();
		final int capacity = buffer.capacity();

		final int END_OF_STREAM = -1;
		int byteRead = 0;
		int startPosition = 0;
		while (byteRead != END_OF_STREAM) {
			int lenToRead = capacity - startPosition;
			System.out.println("Start position: " + startPosition + " Length to read: " + lenToRead);
			// @NathanEckert , about https://github.com/aws/amazon-s3-encryption-client-java/issues/300
			// Crypto Tools SOMETIMES got an Assertion Error from
			// https://github.com/aws/aws-sdk-java-v2/blob/2.20.38/utils/src/main/java/software/amazon/awssdk/utils/async/InputStreamSubscriber.java#L110
			// when using the Encryption Client.
			// If we bump our Java SDK dependencies to the latest, which today is 2.26.7,
			// than we never get the Assertion Error.
			// Here is the PR that changes InputStreamSubscriber b/w 2.20.38 and 2.26.7:
			// https://github.com/aws/aws-sdk-java-v2/pull/5201
			// This makes us suspect that something else is going wrong.
			// Otherwise, we cannot detect a difference in behavior between
			// the S3EC V3 Client and the S3 V2 Client with respect to this code.
			byteRead = stream.read(underlyingBuffer, startPosition, lenToRead);
			System.out.println("Read " + byteRead + " bytes");
			startPosition += byteRead;
			if (byteRead == 0) {
				// Crypto Tools cannot get this case to ever occur.
				throw new AssertionError("Looping indefinitely with an encryption client, as startPosition is not increasing");
			}
		}
	}

	public static S3Client getEncryptionClient(final KeyPair keyPair, final Region region) {
		return S3EncryptionClient.builder()
				.rsaKeyPair(keyPair)
				.enableLegacyUnauthenticatedModes(true)
				.wrappedClient(getClient(region))
				.wrappedAsyncClient(getAsyncClient(region))
				.build();
	}

	public static S3Client getClient(final Region region) {
		return S3Client.builder()
				.region(region)
				.credentialsProvider(CREDENTIALS)
				.httpClient(ApacheHttpClient.create())
				.build();
	}

	public static S3AsyncClient getAsyncClient(final Region region) {
		return S3AsyncClient.builder()
				.region(region)
				.credentialsProvider(CREDENTIALS)
				.httpClient(NettyNioAsyncHttpClient.create())
				.build();
	}

	public static KeyPair generateKeyPair(final String publicKeyString, final String privateKeyString) {
		try {
			final KeyFactory factory = KeyFactory.getInstance("RSA");
			final PublicKey publicKey =
					factory.generatePublic(
							new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString.getBytes())));
			final PrivateKey privateKey =
					factory.generatePrivate(
							new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString.getBytes())));
			return new KeyPair(publicKey, privateKey);
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}
}