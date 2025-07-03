package com.kyfb.secret.util;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;

import com.amazonaws.secretsmanager.caching.SecretCache;
import com.amazonaws.secretsmanager.sql.AWSSecretsManagerMSSQLServerDriver;
import com.amazonaws.secretsmanager.util.Config;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
/**
 * Before using this utility, set up your AWS development
 * environment, including your credentials.
 *
 * For more information, see the following documentation topic:
 *
 * https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/get-started.html
 *
 * We recommend that you cache your secret values by using client-side caching.
 *
 * Caching secrets improves speed and reduces your costs. For more information,
 * see the following documentation topic:
 *
 * https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets.html
 */
public class SecretsManagerUtil {
	
	//The volatile keyword ensures that the instance variable is properly published to all threads.
	private static volatile SecretsManagerUtil instance;
	
	private static SecretsManagerClient secretsClient;
	private static SecretCache secretCache;
	
	private static final String COLON_SEPARATOR=":";
	
	private static String AG_DB_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:058264370150:secret:dev-AgencyGoals-DB-L2DWBG";
	
	private static final Logger logger = LogManager.getLogger(SecretsManagerUtil.class);
	
	//prevents instantiation of utility class
	private SecretsManagerUtil() {		
		
		//DefaultAwsRegionProviderChain class that looks for the region in this order
		//1.Check the aws.region system property for the region.
		//2.Check the AWS_REGION environment variable for the region.
		//3.Check the {user.home}/.aws/credentials and {user.home}/.aws/config files for the region.
		//4.If running in EC2, check the EC2 metadata service for the region.
		
		var regionProvider = DefaultAwsRegionProviderChain.builder().build();
		var region = regionProvider.getRegion();
		if(null == region) {
			region = Region.US_EAST_1;
		}
		
		secretsClient = SecretsManagerClient.builder()
                .region(region)               
                .build();
				
		secretCache = new SecretCache(secretsClient);
	}
	
	
	public static SecretsManagerUtil getInstance() {
		//This double-check for instance ensures that only one instance is created, 
		//even if multiple threads enter the synchronized block at the same time. 
        if (instance == null) {
            synchronized (SecretsManagerUtil.class) {
                if (instance == null) {
                    instance = new SecretsManagerUtil();
                }
            }
        }
        return instance;
    }
	
	
	
    /**
     * Retrieve Secret Value in JSON format from AWS Secrets Manager for given secretName
     * Example return JSON String:
     * {"username":"ANS06900131","password":"**********","engine":"sqlserver","host":"npsdbs101.kfbdom1.kyfb.pri","port":"1433","dbname":"AgencyGoalsDEV"}
     * 
     * @param secretName
     */
	public String getSecretUsingSecretsManager(String secretName) {
        String secret = null;
        try {
            GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
                    .secretId(secretName)
                    .build();

            GetSecretValueResponse valueResponse = secretsClient.getSecretValue(valueRequest);
            secret = valueResponse.secretString();
            logger.info("Secret from Secrets Manager: {}", secret);

        } catch (SecretsManagerException e) {
            logger.error("Error retrieving secret: {}", e.awsErrorDetails().errorMessage());
            System.exit(1);
        }

        return secret;
    }
    
	public GetSecretValueResponse getSecretResponseUsingSecretsManager(String secretName) {
        GetSecretValueResponse valueResponse = null;
        try {
            GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
                    .secretId(secretName)
                    .build();

            valueResponse = secretsClient.getSecretValue(valueRequest);
            logger.info("valueResponse returned from Secrets Manager");

        } catch (SecretsManagerException e) {
            logger.error("Error retrieving secret response: {}", e.awsErrorDetails().errorMessage());
            System.exit(1);
        }

        return valueResponse;
    }
    
    /**
     * Retrieve Secret String Value in JSON format from Secrets Cache for given secretName
     * Example return JSON String:
     * {"username":"ANS06900131","password":"**********","engine":"sqlserver","host":"npsdbs101.kfbdom1.kyfb.pri","port":"1433","dbname":"AgencyGoalsDEV"}
     * 
     * @param secretName
     * @return
     */
	public String getSecretStringFromCache(String secretName) {
        String secretValue = null;
        try {
            secretValue = secretCache.getSecretString(secretName);
            logger.info("Secret from Cache: {}", secretValue);

        } catch (SecretsManagerException e) {
            logger.error("Error retrieving secret from cache: {}", e.awsErrorDetails().errorMessage());
            System.exit(1);
        }

        return secretValue;
    }
    
	public UserCredentials getUserCredentialsFromCache(String secretName) {
        UserCredentials user = null;
        try {
            String secretValue = secretCache.getSecretString(secretName);
            logger.info("Secret from Cache: {}", secretValue);
            user = parseSecretString(secretValue);

        } catch (SecretsManagerException e) {
            logger.error("Error retrieving user credentials from cache: {}", e.awsErrorDetails().errorMessage());
            System.exit(1);
        }

        return user;
    }
    
	public Map getSecretValuesInMap(String secretName) {
        Map secretMap = null;
        try {
            String secretValue = secretCache.getSecretString(secretName);
            logger.info("Secret from Cache: {}", secretValue);
            secretMap = convertJsonToHashMap(secretValue);
            logger.info("Secret map: {}", secretMap);

        } catch (SecretsManagerException e) {
            logger.error("Error retrieving secret values in map: {}", e.awsErrorDetails().errorMessage());
            System.exit(1);
        } catch (IOException e) {
            logger.error("Error converting JSON to HashMap: {}", e.getMessage());
        }

        return secretMap;
    }
    
    
    
    /**
     * @param secretName format: secretName:attributeName
     * @return
     */
	 public String getSecretPropertyValue(String secretName) {
	        Map secretMap = null;
	        String secret = null;
	        String secretAttr = null;
	        String attributeValue = null;

	        try {
	            logger.info("Tomcat Param: {}", secretName);
	            secret = secretName.substring(0, secretName.indexOf(COLON_SEPARATOR));

	            logger.info("Secret from Cache: {}", secretCache.getSecretString(secret));
	            secretMap = convertJsonToHashMap(secretCache.getSecretString(secret));

	            secretAttr = secretName.substring(secretName.indexOf(COLON_SEPARATOR) + 1);
	            logger.info("Key requested: {}", secretAttr);

	            attributeValue = (String) secretMap.get(secretAttr);
	            logger.info("Value returned: {}", attributeValue);

	            logger.info("Secret map: {}", secretMap);
	        } catch (SecretsManagerException e) {
	            logger.error("Error retrieving secret property value: {}", e.awsErrorDetails().errorMessage());
	            System.exit(1);
	        } catch (IOException e) {
	            logger.error("Error converting JSON to HashMap: {}", e.getMessage());
	        }

	        return attributeValue;
	    }
    
    /**
     * Retrieve Secret Binary Value from Secrets Cache for given secretName
     * Example return JSON String:
     * {"username":"ANS06900131","password":"**********","engine":"sqlserver","host":"npsdbs101.kfbdom1.kyfb.pri","port":"1433","dbname":"AgencyGoalsDEV"}
     * 
     * @param secretName
     * @return
     */
	 public ByteBuffer getSecretBinaryFromCache(String secretName) {
	        ByteBuffer secretValue = null;
	        try {
	            secretValue = secretCache.getSecretBinary(secretName);
	            logger.info("Secret Binary from Cache: {}", secretValue);

	        } catch (SecretsManagerException e) {
	            logger.error("Error retrieving secret binary from cache: {}", e.awsErrorDetails().errorMessage());
	            System.exit(1);
	        }

	        return secretValue;
	    }
    
    
    /**
     * Provides the database connection using AWSSecretsManagerMSSQLServerDriver for given ARN.
     * The ARN must be configured within secretsmanager.properties file to avoid calling secrets manager to get ARN.
     * The down side of this approach is to configure ARN for every database that application interacting with.
     * 
     * @return
     */
	 public Connection getAgencyGoalsDBConnection() {
	        Connection con = null;
			// By default it loads properties from secretsmanager.properties file
	        Config secretMngrConfig = Config.loadMainConfig();
	        
	        // Retrieve the connection info (dbname, port and host) from the secret using the secret ARN (Amazon Resource Name)
	        String urlForARN = secretMngrConfig.getStringPropertyWithDefault("agencygoals.db.secret.arn",
	                AG_DB_SECRET_ARN);

		// OR Set the host, port and database name as part of URL like below example
		// String URL = "jdbc-secretsmanager:sqlserver://npsdbs101.kfbdom1.kyfb.pri:1433;databaseName=AgencyGoalsDEV;encrypt=false;";		

		// Populate the user property with the secret ARN to retrieve user and password from the secret
	        Properties info = new Properties();
	        info.put("user", urlForARN);

			// Establish the connection
	        try {
	            new AWSSecretsManagerMSSQLServerDriver(secretCache);
	            con = DriverManager.getConnection(urlForARN, info);

	        } catch (SQLException e) {
	            logger.error("Error establishing database connection: {}", e.getMessage());
	            System.exit(1);
	        }

	        return con;
	    }

    
    /**
     * Provides the database connection using AWSSecretsManagerMSSQLServerDriver for given secret Name.
     * first it retrieves the Secret ARN using secret name, then it uses AWSSecretsManagerMSSQLServerDriver 
     * to create database connection. The down side of this approach is that calling secrets manager twice.
     * @param region
     * @param secretName
     * @return
     */
    public Connection getDBConnectionUsingSecretId(String secretName) { 
    	Connection con = null;
    	String arnforSecret = null;
    	
    	 try {
        	 
             GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
                     .secretId(secretName)
                     .build();

             GetSecretValueResponse valueResponse = secretsClient.getSecretValue(valueRequest);
             arnforSecret = valueResponse.arn();
             logger.info("ARN from Secrets Manager: {}", arnforSecret);
             
         } catch (SecretsManagerException e) {
        	 logger.error("Error retrieving ARN from Secrets Manager: {}", e.awsErrorDetails().errorMessage());
             System.exit(1);
         }
    	 
    	 
    	// Populate the user property with the secret ARN to retrieve user and password from the secret
 		Properties info = new Properties();
 		info.put("user", arnforSecret);

 		// Establish the connection
 		try {
 			 			
 			new AWSSecretsManagerMSSQLServerDriver(secretCache);

 			//ARN will be used as DB URL 
 			con = DriverManager.getConnection(arnforSecret, info);

 			//Statement stmt = con.createStatement();

 			//String SQL = "SELECT TOP 10 * FROM dbo.Agency";
 			//ResultSet rs = stmt.executeQuery(SQL);

 			// Iterate through the data in the result set and display it.
 			//while (rs.next()) {
 			//	System.out.println(rs.getString("AgencyId") + " " + rs.getString("AusRepNm"));
 			//}
 		} catch (SQLException e) {
 			logger.error("Error establishing database connection: {}", e.getMessage());
            System.exit(1);;
 		}
 		
 		return con;
    }
       
    
    /**
     * Method to force the refresh of a cached secret state
     * @param secretId
     * @return
     */
    public boolean refreshNow(String secretId) {
    	boolean refreshFlag = false;
    	
    	try {    		   		
    		
    		refreshFlag = secretCache.refreshNow(secretId);
       	 
       	 
    	 } catch (SecretsManagerException e) {
    		 logger.error("Error refreshing secret: {}", e.awsErrorDetails().errorMessage());
             System.exit(1);
         } catch (InterruptedException e) {
        	 logger.error("Error refreshing secret: {}", e.getMessage());
		}
    	return refreshFlag;
    }
    
    /**
	 * Parse Secret Value to Database credentials
	 * 
	 * Important Note: Do not try to print confidential information (e.g. database
	 * credentials) to CloudWatch console.
	 * 
	 * @param secretString
	 * @return
	 */
	private UserCredentials parseSecretString(String secretString) {
		Gson gson = new Gson();
		UserCredentials user = new UserCredentials();
		
		
		JsonElement element = gson.fromJson(secretString, JsonElement.class);
		JsonObject jsonObject = element.getAsJsonObject();
		user.setUserName(jsonObject.get("username").getAsString());
		user.setPassword(jsonObject.get("password").getAsString());
		
		return user;
	}
	
	private static Map<String, Object> convertJsonToHashMap(String jsonString) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(jsonString, new TypeReference<Map<String, Object>>() {});
    }
       
}

