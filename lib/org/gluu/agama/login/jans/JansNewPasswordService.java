package org.gluu.agama.login.jans;

import io.jans.agama.engine.service.FlowService;
import io.jans.as.common.model.common.User;
import io.jans.as.server.service.AuthenticationService;
import io.jans.as.server.service.UserService;
import io.jans.orm.model.base.CustomObjectAttribute;
import io.jans.service.CacheService;
import io.jans.service.cdi.util.CdiUtil;
import org.gluu.agama.login.NewPasswordService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.jans.agama.engine.script.LogUtils;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.stream.Collectors;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import io.jans.service.net.NetworkService;
import jakarta.servlet.http.HttpServletRequest;


public class JansNewPasswordService extends NewPasswordService {

    private static final Logger logger = LoggerFactory.getLogger(FlowService.class);
    public static final String JANS_STATUS = "jansStatus";
    public static final String INACTIVE = "inactive";
    public static final String ACTIVE = "active";
    public static final String CACHE_PREFIX = "lock_user_";
    private static final String PHONE_NUMBER = "mobile";
    private static final String LANG = "lang";
    private static final String PHONE_VERIFIED = "phoneNumberVerified";
    private static final int OTP_LENGTH = 6;
    private static final int OTP_CODE_LENGTH = 6;
    private static AuthenticationService authenticationService = CdiUtil.bean(AuthenticationService.class);
    private static UserService userService = CdiUtil.bean(UserService.class);
    private static CacheService cacheService = CdiUtil.bean(CacheService.class);
    private String INVALID_LOGIN_COUNT_ATTRIBUTE = "jansCountInvalidLogin";
    private int DEFAULT_MAX_LOGIN_ATTEMPT = 3;
    private int DEFAULT_LOCK_EXP_TIME = 180;
    private static final Map<String, List<Long>> ipAccessLog = new HashMap<>();
    private Set<String> whitelistedIps = new HashSet<>();

    private HashMap<String, String> flowConfig;
    private static final Map<String, String> otpStore = new HashMap<>();

    public JansNewPasswordService(HashMap config) {
        logger.info("Flow config provided is  {}.", config);
        flowConfig = config;
        DEFAULT_MAX_LOGIN_ATTEMPT = flowConfig.get("maxLoginAttempt") != null ? flowConfig.get("maxLoginAttempt") : DEFAULT_MAX_LOGIN_ATTEMPT;
        DEFAULT_LOCK_EXP_TIME = flowConfig.get("lockExpTime") != null ? flowConfig.get("lockExpTime") : DEFAULT_LOCK_EXP_TIME;
    }

    public JansNewPasswordService() {
    }

    private boolean isWhitelistedIp(String ip) {
        try {
            String list = flowConfig.get("WHITELISTED_IPS");
            if (list == null || ip == null)
                return false;

            return Arrays.stream(list.split(","))
                    .map(String::trim)
                    .anyMatch(ip::equals);

        } catch (Exception e) {
            logger.error("Whitelist check failed: {}", e.getMessage());
            return false;
        }
    }

    private void logIncomingHeaders() {
        try {
            HttpServletRequest request = CdiUtil.bean(HttpServletRequest.class);

            LogUtils.log("|+++++++++++++++++++++++++++++++++++++| ===== Incoming Headers =====");

            Enumeration<String> headerNames = request.getHeaderNames();
            if (headerNames == null) {
                LogUtils.log("|+++++++++++++++++++++++++++++++++++++| No headers found.");
                return;
            }

            while (headerNames.hasMoreElements()) {
                String header = headerNames.nextElement();
                String value = request.getHeader(header);
                LogUtils.log("|org.gluu.agama.change.phonenumber| HEADER: {} = {}", header, value);
            }

            LogUtils.log("|org.gluu.agama.change.phonenumber| ===========================");

        } catch (Exception e) {
            LogUtils.log("|org.gluu.agama.change.phonenumber| Failed to log headers: {}", e.getMessage());
        }
    }

    private String extractClientIp() {
        try {
            HttpServletRequest request = CdiUtil.bean(HttpServletRequest.class);

            // 1️⃣ Check X-Forwarded-For first (most reliable)
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isEmpty()) {
                // Handles multiple IPs: "10.1.1.1, 192.168.1.10"
                return xff.split(",")[0].trim();
            }

            // 2️⃣ fallback to remote address
            return request.getRemoteAddr();
        } catch (Exception e) {
            LogUtils.log("Failed to extract client IP: {}", e.getMessage());
            return "127.0.0.1";
        }
    }

    @Override
    public boolean validate(String username, String password) {
        logger.info("Validating user credentials.");
        boolean hasLogin = authenticationService.authenticate(username, password);
        if (hasLogin && Boolean.valueOf(flowConfig.get("ENABLE_ACCOUNT_LOCK"))) {
            logger.info("Credentials are valid and user account locked feature is activated");
            User currentUser = userService.getUser(username);
            userService.setCustomAttribute(currentUser, INVALID_LOGIN_COUNT_ATTRIBUTE, 0);
            userService.updateUser(currentUser);
            logger.info("Invalid login count reset to zero for {} .", username);
        }
        return hasLogin;
    }

    @Override
    public String lockAccount(String username) {
        User currentUser = userService.getUser(username);
        if (currentUser == null) {
            LogUtils.log("User % not found. Cannot lock account.", username);
            return "User not found. Cannot proceed with account lock.";
        }        
        int currentFailCount = 1;
        String invalidLoginCount = getCustomAttribute(currentUser, INVALID_LOGIN_COUNT_ATTRIBUTE);
        if (invalidLoginCount != null) {
            currentFailCount = Integer.parseInt(invalidLoginCount) + 1;
        }
        String currentStatus = getCustomAttribute(currentUser, JANS_STATUS);
        logger.info("Current user status is: {}", currentStatus);
        if (currentFailCount < DEFAULT_MAX_LOGIN_ATTEMPT) {
            int remainingCount = DEFAULT_MAX_LOGIN_ATTEMPT - currentFailCount;
            logger.info("Remaining login count: {} for user {}", remainingCount, username);
            if (remainingCount > 0 && currentStatus == "active") {
                setCustomAttribute(currentUser, INVALID_LOGIN_COUNT_ATTRIBUTE, String.valueOf(currentFailCount));
                logger.info("{}  more attempt(s) before account is LOCKED!", remainingCount);
            }
            return "You have " + remainingCount + " more attempt(s) before your account is locked.";
        }
        if (currentFailCount >= DEFAULT_MAX_LOGIN_ATTEMPT && currentStatus == "active") {
            logger.info("Locking {} account for {} seconds.", username, DEFAULT_LOCK_EXP_TIME);
            String object_to_store = "{'locked': 'true'}";
            setCustomAttribute(currentUser, JANS_STATUS, INACTIVE);
            cacheService.put(DEFAULT_LOCK_EXP_TIME, CACHE_PREFIX + username, object_to_store);
            return "Your account have been locked.";
        }
        if (currentFailCount >= DEFAULT_MAX_LOGIN_ATTEMPT && currentStatus == "inactive") {
            logger.info("User {} account is already locked. Checking if we can unlock", username);
            String cache_object = cacheService.get(CACHE_PREFIX + username);
            if (cache_object == null) {
                logger.info("Unlocking user {} account", username);
                setCustomAttribute(currentUser, JANS_STATUS, ACTIVE);
                setCustomAttribute(currentUser, INVALID_LOGIN_COUNT_ATTRIBUTE, "0");
                return "Your account  is now unlock. Try login ";
            }

        }
        return null;
    }

    private String getCustomAttribute(User user, String attributeName) {
        CustomObjectAttribute customAttribute = userService.getCustomAttribute(user, attributeName);
        if (customAttribute != null) {
            return customAttribute.getValue();
        }
        return null;
    }

    private User setCustomAttribute(User user, String attributeName, String value) {
        userService.setCustomAttribute(user, attributeName, value);
        return userService.updateUser(user);
    }

    public boolean isPhoneVerified(String username) {
        try {
            User user = userService.getUser(username);
            if (user == null) return false;

            Object val = user.getAttribute("phoneNumberVerified", true, false);
            return val != null && Boolean.parseBoolean(val.toString());
        } catch (Exception e) {
            logger.error("Error checking phone verification for {}: {}", username, e.getMessage(), e);
            return false;
        }
    }

    public boolean isPhoneUnique(String username, String phone) {
        try {
            // Normalize phone number
            String normalizedPhone = phone.startsWith("+") ? phone : "+" + phone;

            // Check DB for existing users
            List<User> users = userService.getUsersByAttribute("mobile", normalizedPhone, true, 10);

            if (users != null && !users.isEmpty()) {
                for (User u : users) {
                    if (!u.getUserId().equalsIgnoreCase(username)) {
                        logger.info("Phone {} is NOT unique. Already used by {}", phone, u.getUserId());
                        return false; // duplicate
                    }
                }
            }

            logger.info("Phone {} is unique", phone);
            return true;
        } catch (Exception e) {
            logger.error("Error checking phone uniqueness for {}", phone, e);
            return false; // safest default on error
        }
    }


    public String getPhoneNumber(String username) {
        try {
            User user = userService.getUser(username);
            if (user == null) return null;
            Object phone = user.getAttribute("PHONE_NUMBER", true, false);
            return phone != null ? phone.toString() : null;
        } catch (Exception e) {
            logger.error("Error fetching phone number for {}: {}", username, e.getMessage(), e);
            return null;
        }
    }


    public String markPhoneAsVerified(String username, String phone) {
        try {
            User user = userService.getUser(username);
            if (user == null) {
                logger.warn("User {} not found while marking phone verified", username);
                return "User not found.";
            }

            // Set the phone number and mark it as verified
            user.setAttribute(PHONE_NUMBER, phone);
            user.setAttribute("phoneNumberVerified", Boolean.TRUE);
            userService.updateUser(user);

            logger.info("Phone {} verified and updated for user {}", phone, username);
            return "Phone " + phone + " verified successfully for user " + username;
        } catch (Exception e) {
            logger.error("Error marking phone verified for {}: {}", username, e.getMessage(), e);
            return "Error: " + e.getMessage();
        }
    }

    private String generateSMSOtpCode(int codeLength) {
        String numbers = "0123456789";
        SecureRandom random = new SecureRandom();
        char[] otp = new char[codeLength];
        for (int i = 0; i < codeLength; i++) {
            otp[i] = numbers.charAt(random.nextInt(numbers.length()));
        }
        return new String(otp);
    }

    public boolean sendOTPCode(String username, String phone) {

        logIncomingHeaders(); // Log headers for debugging

        String clientIp = extractClientIp(); // ✅ Read stored IP instead of parameter

        logger.info("Using IP {} for OTP request of user {}", clientIp, phone);

        // ✅ Enforce resend rate limit
        if (isIpBlocked(clientIp)) {
            logger.info("IP {} is blocked for 24h due to excessive OTP requests", clientIp);
            return null;
            }

            recordOtpAttempt(clientIp); // ✅ Record attempt with stored IP
            logger.info("✅ OTP attempt recorded for IP {} (Total: {})", clientIp, ipAccessLog.get(clientIp).size());

        try {
            // Get user preferred language from profile
            User user = userService.getUser(username);
            String lang = null;
            if (user != null) {
                Object val = user.getAttribute("LANG", true, false);
                if (val != null) {
                    lang = val.toString().toLowerCase();
                }
            }
            if (lang == null || lang.isEmpty()) {
                lang = "en";
            }

            // Generate OTP
            String otpCode = generateSMSOtpCode(OTP_LENGTH);
            otpStore.put(phone, otpCode);
            logger.info("Generated OTP {} for phone {}", otpCode, phone);

            // Localized message
            Map<String, String> messages = new HashMap<>();

            messages.put("ar", "رمز التحقق OTP الخاص بك من Phi Wallet هو " + otpCode + ". لا تشاركه مع أي شخص.");
            messages.put("en", "Your Phi Wallet OTP is " + otpCode + ". Do not share it with anyone.");
            messages.put("es", "Tu código de Phi Wallet es " + otpCode + ". No lo compartas con nadie.");
            messages.put("fr", "Votre code Phi Wallet est " + otpCode + ". Ne le partagez avec personne.");
            messages.put("id", "Kode Phi Wallet Anda adalah " + otpCode + ". Jangan bagikan kepada siapa pun.");
            messages.put("pt", "O seu código da Phi Wallet é " + otpCode + ". Não o partilhe com ninguém.");
            
            String message = messages.getOrDefault(lang, messages.get("en"));

            // Determine which FROM_NUMBER to use based on country code
            String fromNumber = getFromNumberForPhone(phone);
            
            if (fromNumber == null || fromNumber.trim().isEmpty()) {
                logger.error("FROM_NUMBER is null or empty, cannot send OTP to {}", phone);
                return false;
            }

            // Send SMS
            PhoneNumber FROM_NUMBER = new PhoneNumber(fromNumber);
            PhoneNumber TO_NUMBER = new PhoneNumber(phone);

            Twilio.init(flowConfig.get("ACCOUNT_SID"), flowConfig.get("AUTH_TOKEN"));
            Message.creator(TO_NUMBER, FROM_NUMBER, message).create();

            logger.info("OTP sent to {} using sender {}", phone, fromNumber);
            return true;
        } catch (Exception ex) {
            logger.error("Failed to send OTP to {}. Error: {}", phone, ex.getMessage(), ex);
            return false;
        }
    }

    public boolean validateOTPCode(String phone, String code) {
        try {
            String storedCode = otpStore.getOrDefault(phone, "NULL");
            logger.info("User submitted code: {} — Stored code: {}", code, storedCode);
            if (storedCode.equalsIgnoreCase(code)) {
                otpStore.remove(phone); // remove after successful validation
                return true;
            }
            return false;
        } catch (Exception ex) {
            logger.error("Error validating OTP {} for phone {}: {}", code, phone, ex.getMessage(), ex);
            return false;
        }
    }

    /**
     * Determines which FROM_NUMBER to use based on the phone number's country code.
     * Priority: 1) Countries in US_COUNTRY_CODES use FROM_NUMBER_US, 
     *          2) Countries in RESTRICTED_COUNTRY_CODES use FROM_NUMBER_RESTRICTED_COUNTRIES,
     *          3) All others use default FROM_NUMBER.
     */
    private String getFromNumberForPhone(String phone) {
        try {
            logger.info("=== getFromNumberForPhone START: phone='{}' ===", phone);
            String defaultFromNumber = flowConfig.get("FROM_NUMBER");
            String usCountryCodes = flowConfig.get("US_COUNTRY_CODES");
            String restrictedCodes = flowConfig.get("RESTRICTED_COUNTRY_CODES");
            
            logger.info("Config values - FROM_NUMBER: '{}', US_COUNTRY_CODES: '{}', RESTRICTED_CODES: '{}'", 
                       defaultFromNumber, usCountryCodes, restrictedCodes);
            
            if (defaultFromNumber == null || defaultFromNumber.trim().isEmpty()) {
                logger.error("FROM_NUMBER not configured");
                return null;
            }
            
            // Parse US country codes for matching
            Set<String> usCountrySet = new HashSet<>();
            if (usCountryCodes != null && !usCountryCodes.trim().isEmpty()) {
                usCountrySet = java.util.Arrays.stream(usCountryCodes.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
            }
            logger.info("US_COUNTRY_CODES from config: '{}' -> parsed to: {}", usCountryCodes, usCountrySet);
            
            // Parse restricted country codes for matching
            Set<String> restrictedSet = new HashSet<>();
            if (restrictedCodes != null && !restrictedCodes.trim().isEmpty()) {
                restrictedSet = java.util.Arrays.stream(restrictedCodes.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
            }
            
            // Combine both sets for accurate country code extraction
            Set<String> allKnownCodes = new HashSet<>();
            allKnownCodes.addAll(usCountrySet);
            allKnownCodes.addAll(restrictedSet);
            logger.info("Combined allKnownCodes: {}", allKnownCodes);
            
            // Extract country code from phone number
            String countryCode = extractCountryCode(phone, allKnownCodes);
            logger.info("Phone: '{}' -> Extracted country code: '{}'", phone, countryCode);
            
            if (countryCode == null || countryCode.isEmpty()) {
                logger.info("No country code extracted, using default sender");
                return defaultFromNumber;
            }

            // Priority 1: Check if country code is in US_COUNTRY_CODES - use US-specific sender
            logger.info("Checking if country code '{}' is in US_COUNTRY_CODES: {}", countryCode, usCountrySet);
            logger.info("usCountrySet.size(): {}, contains('{}'): {}", usCountrySet.size(), countryCode, usCountrySet.contains(countryCode));
            if (usCountrySet.contains(countryCode)) {
                String usFromNumber = flowConfig.get("FROM_NUMBER_US");
                logger.info("Retrieved FROM_NUMBER_US from config: '{}'", usFromNumber);
                
                if (usFromNumber != null && !usFromNumber.trim().isEmpty()) {
                    logger.info("Using US-specific sender {} for country code {}", usFromNumber, countryCode);
                    return usFromNumber;
                }
            }

            // Priority 2: Check if country code is in restricted list
            logger.info("Checking if country code '{}' is in restricted list: {}", countryCode, restrictedSet);
            if (restrictedSet.contains(countryCode)) {
                String restrictedFromNumber = flowConfig.get("FROM_NUMBER_RESTRICTED_COUNTRIES");
                
                if (restrictedFromNumber != null && !restrictedFromNumber.trim().isEmpty()) {
                    logger.info("Using restricted sender {} for country code {}", restrictedFromNumber, countryCode);
                    return restrictedFromNumber;
                }
            }

            logger.info("No matching category found, returning default sender: {}", defaultFromNumber);
            return defaultFromNumber;
        } catch (Exception ex) {
            logger.error("Error in getFromNumberForPhone: {}", ex.getMessage(), ex);
            return flowConfig.get("FROM_NUMBER");
        }
    }

    /**
     * Extract country code from phone number by matching against known codes.
     * Returns 1-digit code "1" or 2-3 digit country code.
     */
    private String extractCountryCode(String phone, Set<String> knownCodes) {
        logger.info("extractCountryCode: input phone='{}'", phone);
        
        if (phone == null || phone.trim().isEmpty()) {
            return null;
        }

        String cleaned = phone.startsWith("+") ? phone.substring(1) : phone;
        logger.info("extractCountryCode: after removing +, cleaned='{}'", cleaned);
        
        if (cleaned.length() < 2) {
            return null;
        }

        // Handle code "1" first (US/Canada and territories)
        boolean isDigit = cleaned.length() > 1 && Character.isDigit(cleaned.charAt(1));
        logger.info("extractCountryCode: startsWith('1')? {}, length > 1? {}, charAt(1) is digit? {}", 
                    cleaned.startsWith("1"), cleaned.length() > 1, isDigit);
        
        if (cleaned.startsWith("1") && cleaned.length() > 1 && Character.isDigit(cleaned.charAt(1))) {
            logger.info("extractCountryCode: returning '1'");
            return "1";
        }
        
        // Try 3-digit codes ONLY if they're in our knownCodes list
        if (cleaned.length() >= 3 && knownCodes != null && !knownCodes.isEmpty()) {
            String threeDigit = cleaned.substring(0, 3);
            if (knownCodes.contains(threeDigit)) {
                return threeDigit;
            }
        }
        
        // Default: Extract 2-digit country code
        return cleaned.substring(0, 2);
    }

    // SMS-IP-BLOCKING-FIXES
    private void recordOtpAttempt(String clientIp) {
        long now = System.currentTimeMillis();
        long timeWindow = Long.parseLong(flowConfig.getOrDefault("TIME_WINDOW_MS", "86400000"));

        ipAccessLog.compute(clientIp, (key, timestamps) -> {
            if (timestamps == null)
                timestamps = new ArrayList<>();

            // timestamps.removeIf(ts -> now - ts > TIME_WINDOW_MS);
            timestamps.removeIf(ts -> now - ts > timeWindow);
            timestamps.add(now);
            return timestamps;
        });
        // ✅ FIXED: Was using 'ip' instead of 'clientIp'
        logger.info("📊 OTP attempt recorded for IP {} → count: {}", clientIp, ipAccessLog.get(clientIp).size());
    }

    private boolean isIpBlocked(String clientIp) {
        if (isWhitelistedIp(clientIp)) {
            logger.info("IP {} is WHITELISTED — skipping OTP blocking", clientIp);
            return false;
        }
        int maxAttempts = Integer.parseInt(flowConfig.getOrDefault("MAX_SMS_OTP_PER_DAY", "4"));
        long timeWindow = Long.parseLong(flowConfig.getOrDefault("TIME_WINDOW_MS", "86400000"));

        List<Long> timestamps = ipAccessLog.get(clientIp);
        if (timestamps == null)
            return false;

        long now = System.currentTimeMillis();
        timestamps.removeIf(ts -> now - ts > timeWindow);

        boolean blocked = timestamps.size() >= maxAttempts;

        if (blocked) {
            logger.warn("IP {} BLOCKED — Attempts: {} / {}", clientIp, timestamps.size(), maxAttempts);
        }
        return blocked;
    }



}
