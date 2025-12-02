package org.gluu.agama.login;

import org.gluu.agama.login.jans.JansNewPasswordService;

import java.util.HashMap;
import java.util.Map;

public abstract class NewPasswordService {

    public abstract boolean validate(String username, String password);

    public abstract String lockAccount(String username);

    public abstract boolean isPhoneVerified(String username);

    public abstract boolean isPhoneUnique(String username, String phone);

    public abstract String markPhoneAsVerified(String username, String phone);

    public abstract boolean sendOTPCode(String username, String phone);

    public abstract boolean validateOTPCode(String phone, String code);

    public static NewPasswordService getInstance(HashMap config) {
        return new JansNewPasswordService(config);
    }
}
