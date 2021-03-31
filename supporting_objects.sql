BEGIN
EXECUTE IMMEDIATE
'
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "JaaSUtil" AS
import java.lang.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.*;
import java.security.Signature;

public class JaaSUtil {
        private static String QUOTES = "\"";
        public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
        public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
        public static class JaaSHeader {
            private Map<String, Object> headerClaims = new HashMap<String, Object>();
            public JaaSHeader() {}

            public JaaSHeader withApiKey(String apiKey) {
                headerClaims.put("kid", apiKey);
                return this;
            }

            @Override
            public String toString() {
                StringBuilder header = new StringBuilder();

                header.append("{ \"alg\": \"RS256\" ");

                if (headerClaims.containsKey("kid")) {
                    header.append(",")
                            .append("\"kid\":")
                            .append(JaaSUtil.QUOTES)
                            .append(headerClaims.get("kid"))
                            .append(JaaSUtil.QUOTES);
                }

                header.append(",\"typ\":\"JWT\"}");
                return header.toString();
            }
        };

        public static class JaaSPayload {
            private Map<String, Object> payloadClaims = new HashMap<String, Object>();
            private Map<String, Object> userClaims = new HashMap<String, Object>();
            private Map<String, Object> featureClaims = new HashMap<String, Object>();

            public JaaSPayload() { }

            public JaaSPayload withUserName(String userName) {
                userClaims.put("name", userName);
                return this;
            }

            public JaaSPayload withUserAvatar(String userAvatar) {
                userClaims.put("avatar", userAvatar);
                return this;
            }

            public JaaSPayload withUserEmail(String userEmail) {
                userClaims.put("email", userEmail);
                return this;
            }

            public JaaSPayload withUserId(String userId) {
                userClaims.put("id", userId);
                return this;
            }

            public JaaSPayload withModerator(boolean isModerator) {
                userClaims.put("moderator", Boolean.valueOf(isModerator));
                return this;
            }

            public JaaSPayload withLiveStreamingEnabled(boolean isEnabled) {
                featureClaims.put("livestreaming", Boolean.valueOf(isEnabled));
                return this;
            }

            public JaaSPayload withRecordingEnabled(boolean isEnabled) {
                featureClaims.put("recording", Boolean.valueOf(isEnabled));
                return this;
            }

            public JaaSPayload withOutboundEnabled(boolean isEnabled) {
                featureClaims.put("outbound-call", Boolean.valueOf(isEnabled));
                return this;
            }

            public JaaSPayload withTranscriptionEnabled(boolean isEnabled) {
                featureClaims.put("transcription", Boolean.valueOf(isEnabled));
                return this;
            }

            public JaaSPayload withExpTime(long expTime) {
                payloadClaims.put("exp", Long.valueOf(expTime));
                return this;
            }

            public JaaSPayload withNbfTime(long nbfTime) {
                payloadClaims.put("nbf", Long.valueOf(nbfTime));
                return this;
            }

            public JaaSPayload withRoomName(String roomName) {
                payloadClaims.put("room", roomName);
                return this;
            }

            public JaaSPayload withAppID(String appId) {
                payloadClaims.put("sub", appId);
                return this;
            }

            private String getFeatureClaimsString() {
                StringBuilder featureClaimsBuilder = new StringBuilder();
                featureClaimsBuilder.append("\"features\":{");

                if (featureClaims.containsKey("livestreaming")) {
                    featureClaimsBuilder.append("\"livestreaming\":")
                            .append(JaaSUtil.QUOTES)
                            .append( ((Boolean)featureClaims.get("livestreaming")) ? "true" : "false" )
                            .append(JaaSUtil.QUOTES);
                }

                if (featureClaims.containsKey("recording")) {
                    featureClaimsBuilder.append(",\"recording\":")
                            .append(JaaSUtil.QUOTES)
                            .append( ((Boolean)featureClaims.get("recording")) ? "true" : "false")
                            .append(JaaSUtil.QUOTES);
                }

                if (featureClaims.containsKey("outbound-call")) {
                    featureClaimsBuilder.append(",\"outbound-call\":")
                            .append(JaaSUtil.QUOTES)
                            .append( ((Boolean)featureClaims.get("outbound-call")) ? "true" : "false")
                            .append(JaaSUtil.QUOTES);
                }

                if (featureClaims.containsKey("transcription")) {
                    featureClaimsBuilder.append(",\"transcription\":")
                            .append(JaaSUtil.QUOTES)
                            .append( ((Boolean)featureClaims.get("transcription")) ? "true" : "false")
                            .append(JaaSUtil.QUOTES);
                }

                featureClaimsBuilder.append("}");

                return featureClaimsBuilder.toString();
            }

            private String getUserClaimsString() {
                StringBuilder userClaimsBuilder = new StringBuilder();
                userClaimsBuilder.append("\"user\":{");

                if (userClaims.containsKey("id")) {
                    userClaimsBuilder.append("\"id\":")
                            .append(JaaSUtil.QUOTES)
                            .append(userClaims.get("id"))
                            .append(JaaSUtil.QUOTES);
                }

                if (userClaims.containsKey("name")) {
                    userClaimsBuilder.append(",")
                            .append("\"name\":")
                            .append(JaaSUtil.QUOTES)
                            .append(userClaims.get("name"))
                            .append(JaaSUtil.QUOTES);
                }

                if (userClaims.containsKey("avatar")) {
                    userClaimsBuilder.append(",")
                            .append("\"avatar\":")
                            .append(JaaSUtil.QUOTES)
                            .append(userClaims.get("avatar"))
                            .append(JaaSUtil.QUOTES);
                }

                if (userClaims.containsKey("email")) {
                    userClaimsBuilder.append(",")
                            .append("\"email\":")
                            .append(JaaSUtil.QUOTES)
                            .append(userClaims.get("email"))
                            .append(JaaSUtil.QUOTES);
                }

                if (userClaims.containsKey("moderator")) {
                    userClaimsBuilder.append(",")
                            .append("\"moderator\":")
                            .append(JaaSUtil.QUOTES)
                            .append( ((Boolean)userClaims.get("moderator")) ? "true" : "false")
                            .append(JaaSUtil.QUOTES);
                }

                userClaimsBuilder.append("}");

                return userClaimsBuilder.toString();
            }

            @Override
            public String toString() {
                StringBuilder payloadBuilder = new StringBuilder()
                        .append("{ \"aud\" : \"jitsi\" , \"iss\" : \"chat\" ");

                if (payloadClaims.containsKey("exp")) {
                    payloadBuilder.append(",")
                            .append("\"exp\":")
                            .append( ((Long) payloadClaims.get("exp")).toString() );
                }

                if (payloadClaims.containsKey("nbf")) {
                    payloadBuilder.append(",")
                            .append("\"nbf\":")
                            .append( ((Long) payloadClaims.get("nbf")).toString() );
                }

                if (payloadClaims.containsKey("room")) {
                    payloadBuilder.append(",")
                            .append("\"room\":")
                            .append(JaaSUtil.QUOTES)
                            .append(payloadClaims.get("room"))
                            .append(JaaSUtil.QUOTES);
                }

                if (payloadClaims.containsKey("sub")) {
                    payloadBuilder.append(",")
                            .append("\"sub\":")
                            .append(JaaSUtil.QUOTES)
                            .append(payloadClaims.get("sub"))
                            .append(JaaSUtil.QUOTES);
                }

                payloadBuilder.append(",")
                        .append("\"context\":{")
                        .append(getUserClaimsString())
                        .append(",")
                        .append(getFeatureClaimsString())
                        .append("}");

                payloadBuilder.append("}");

                return payloadBuilder.toString();
            }
        }

        public static String getHeader(String apiKey) {
            String header = (new JaaSHeader())
                    .withApiKey(apiKey).toString();
            return header;
        }

        public static String getPayload(String userId,
                                        String userName,
                                        String userAvatar,
                                        String userEmail,
                                        boolean isModerator,
                                        boolean livestreamingEnabled,
                                        boolean recordingEnabled,
                                        boolean outboundEnabled,
                                        boolean transcriptionEnabled,
                                        Long exptime,
                                        Long nbfTime,
                                        String roomName,
                                        String AppID) {
            String payload = (new JaaSPayload())
                    .withUserEmail(userEmail)
                    .withUserName(userName)
                    .withUserId(userId)
                    .withUserAvatar(userAvatar)
                    .withAppID(AppID)
                    .withExpTime(exptime)
                    .withNbfTime(nbfTime)
                    .withRoomName(roomName)
                    .withModerator(isModerator)
                    .withLiveStreamingEnabled(livestreamingEnabled)
                    .withOutboundEnabled(outboundEnabled)
                    .withRecordingEnabled(recordingEnabled)
                    .withTranscriptionEnabled(transcriptionEnabled)
                    .toString();

            return payload;
        }

        private static String cleanupKey(String privateKey) {
            int bpos = privateKey.lastIndexOf(JaaSUtil.BEGIN_PRIVATE_KEY);
            privateKey = privateKey.substring(bpos + JaaSUtil.BEGIN_PRIVATE_KEY.length());
            int epos = privateKey.lastIndexOf(JaaSUtil.END_PRIVATE_KEY);
            privateKey = privateKey.substring(0, epos);
            return privateKey;
        }

        public static String getJWT(String apiKey,
                                    String userId,
                                    String userName,
                                    String userAvatar,
                                    String userEmail,
                                    int isModerator,
                                    int livestreamingEnabled,
                                    int recordingEnabled,
                                    int outboundEnabled,
                                    int transcriptionEnabled,
                                    Long exptime,
                                    Long nbfTime,
                                    String roomName,
                                    String AppID,
                                    String pKey) {

            try
            {
                boolean check = pKey.contains(JaaSUtil.BEGIN_PRIVATE_KEY) && pKey.contains(JaaSUtil.END_PRIVATE_KEY);
                if (!check) {
                    return "FAILED : Please make sure the specified private key is correctly formatted.";
                }

                String header = getHeader(apiKey);
                String payload = getPayload(userId,userName,userAvatar,userEmail,isModerator > 0,livestreamingEnabled > 0,
                        recordingEnabled > 0,outboundEnabled > 0,transcriptionEnabled > 0,exptime,nbfTime,roomName,AppID);

                byte[] encodedBytesHeader = Base64.getUrlEncoder().withoutPadding().encode(header.getBytes(StandardCharsets.UTF_8));
                byte[] encodedBytesPayload = Base64.getUrlEncoder().withoutPadding().encode(payload.getBytes(StandardCharsets.UTF_8));
                String encodedHeader = new String(encodedBytesHeader, StandardCharsets.UTF_8);
                String encodedPayload = new String(encodedBytesPayload, StandardCharsets.UTF_8);
                String content = encodedHeader + "." + encodedPayload;
                String privateKey = JaaSUtil.cleanupKey(pKey);
                byte[] decoded = Base64.getMimeDecoder().decode(privateKey);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                RSAPrivateKey rsaKey = (RSAPrivateKey) kf.generatePrivate(spec);
                Signature rsaSha256Signature = Signature.getInstance("SHA256withRSA");
                rsaSha256Signature.initSign(rsaKey);
                rsaSha256Signature.update(content.getBytes(StandardCharsets.UTF_8));
                byte[] signatureBytes = rsaSha256Signature.sign();
                String encodedSignature = new String(Base64.getUrlEncoder().withoutPadding().encode(signatureBytes), StandardCharsets.UTF_8);
                String token = content + "." + encodedSignature;
                return token;
            }
            catch (Exception ex) {
                return ex.getMessage();
            }
        }
    };
';
END;


create or replace FUNCTION JAAS_GET_JWT(API_KEY IN varchar2,USER_ID IN varchar2,USER_NAME IN varchar2,USER_AVATAR IN varchar2,USER_EMAIL IN varchar2,IS_MODERATOR IN NUMBER,LIVESTREAMING_ENABLED IN NUMBER,RECORDING_ENABLED IN NUMBER,OUTBOUND_ENABLED IN NUMBER,TRANSCRIPTION_ENABLED IN NUMBER,EXP_UNIX_TIME IN NUMBER,NBF_UNIX_TIME IN NUMBER,ROOM_NAME IN varchar2,APP_ID IN varchar2,PRIVATE_KEY IN varchar2)
	RETURN varchar2
AS LANGUAGE JAVA NAME 'JaaSUtil.getJWT(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, int, int, int, int, int, java.lang.Long, java.lang.Long, java.lang.String, java.lang.String, java.lang.String) return java.lang.String';


create or replace function JAAS_GET_JWT_NOW(API_KEY IN varchar2,USER_ID IN varchar2,USER_NAME IN varchar2,USER_AVATAR IN varchar2,USER_EMAIL IN varchar2,IS_MODERATOR IN NUMBER,LIVESTREAMING_ENABLED IN NUMBER,RECORDING_ENABLED IN NUMBER,OUTBOUND_ENABLED IN NUMBER,TRANSCRIPTION_ENABLED IN NUMBER,ROOM_NAME IN varchar2,APP_ID IN varchar2,PRIVATE_KEY IN varchar2) return varchar2 is

	l_unix_ts number;
	l_exp_time number;
	l_nbf_time number;
	jwt varchar2(32767);
begin
	l_unix_ts := CONVERT_DATE_TO_UNIX_TS(SYSTIMESTAMP);
	l_exp_time := l_unix_ts + 7200;
	l_nbf_time := l_unix_ts;
	jwt := JAAS_GET_JWT(API_KEY, USER_ID, USER_NAME, USER_AVATAR, USER_EMAIL, IS_MODERATOR, LIVESTREAMING_ENABLED, RECORDING_ENABLED, OUTBOUND_ENABLED, TRANSCRIPTION_ENABLED, l_exp_time, l_nbf_time, ROOM_NAME, APP_ID, PRIVATE_KEY);
	return jwt;
end;


