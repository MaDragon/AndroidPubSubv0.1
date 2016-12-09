##
## Added scan/publish BLE sensor data to AWS IoT function, based on pubsub sample
##

1. Download sample code and import it to AS.
2. Import libraries (AS will take care of these) and run the app.

   	`error:java.lang.RuntimeException: Unable to start activity ComponentInfo` 
	Becasue we have not configure the connection setup yet.

3. Create Cognito. 
	In Cognito Console dashboard:

	1. Select “N.Virginia” as region.
	2. Click “Manage Federated Identities”
	3. Click “Create new identity pool”
	4. Enter a unique name to identity pool.
	5. Click “Enable access to unauthenticated identities” checkbox.
	6. Click “Create pool” to the next page, the region in the above bar becomes “Global”. And policy documents for each role shown as below, not the same as tutorial.
	7. Click “Allow” and Obtain the PoolID constant
	In our case, it is “us-east-1:17422d77-40b3-4d9b-991b-a09a7d1f2232” and paste it to change the constants in java code.
4. Set up two roles in IAM (IAM does not require region selection)
	1. Click two roles in IAM
	2. Enter the role and attach policy
	3. Select “AWSIOTFullAccess” and attach policy
	4. Attach the same policy to second role
5. Navigate to the AWS IoT Console and create Policy
   a. Make sure in the same region and create policy
   b. Give the policy a name and paste it to java code
6. Find endpoint of AWS IoT and paste it.
7. The code has been modified as below
8. **Unistall the app** and then build and run the app. It will be successful.

#Below is the original from aws github:
This sample demonstrates use of the AWS IoT APIs to securely publish to and subscribe from MQTT topics.  It uses Cognito authentication in conjunction with AWS IoT to create an identity (client certificate and private key) and store it in a Java keystore.  This identity is then used to authenticate to AWS IoT.  Once a connection to the AWS IoT platform has been established, the application presents a simple UI to publish and subscribe over MQTT.  After certificate and private key have been added to the keystore the app will use these for future connections.

## Requirements

* AndroidStudio or Eclipse
* Android API 10 or greater

## Using the Sample

1. Import the AndroidPubSub project into your IDE.
   - If you are using Android Studio:
      * From the Welcome screen, click on "Import project".
      * Browse to the AndroidPubSub directory and press OK.
      * Accept the messages about adding Gradle to the project.
      * If the SDK reports some missing Android SDK packages (like Build Tools or the Android API package), follow the instructions to install them.
   - If you are using Eclipse:
      * Go to File -> Import. Import Wizard will open.
      * Select General -> Existing Projects into Workspace. Click Next.
      * In Select root directory, browse to the samples directory.
      * Select the AndroidPubSub project to import.
      * Click Finish.
      
1. Import the libraries :
   - If you use Android Studio, Gradle will take care of downloading these dependencies for you.
