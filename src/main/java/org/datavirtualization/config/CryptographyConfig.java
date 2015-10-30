package org.datavirtualization.config;

import java.nio.charset.Charset;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.List;
import java.util.Properties;

import com.fasterxml.jackson.databind.ObjectMapper;

public class CryptographyConfig {
    /** The primary application secret used to check signatures */
    public static final String APP_SECRET = "a1cc5e57cd469950c317c05625edc9dc";

    /** The properties file name. The file should be on the classpath. */
    private static final String       SECRETS_FILE = "classpath:properties/secrets.{0}.properties";

    private static final ObjectMapper jsonMapper = new ObjectMapper();

    protected static final Properties props = new Properties();

    static {
        props.setProperty("app.secret","a1cc5e57cd469950c317c05625edc9dc");
        props.setProperty("","");
    }

    /**
     * Loading a properties file for any environment will also load the
     * environment named with this token, and merge the actual environment down
     * on top of it. Properties files with no environment substitution token
     * will of course not be affected.
     */
    private static final String       TOKEN_COMMON = "common";

    /**
     * Get the cached properties that have been loaded/merged.
     * 
     * @return A single properties instance that includes properties from the
     *         environment specific properties file merged on top of the common
     *         properties file.
     * 
     * @see AbstractConfig#loadPropsFrom(String, Properties)
     */
    public static Properties getProperties() {
        return props;
    }

    /**
     * The Encoding mechanism of the characters data for the application. this
     * is to be checked against Jvm's encoding, and affects quickHealth in
     * health monitor. The purpose of this is to prevent misconfigured servers
     * from being included in the server pool.
     */
    public static final String APP_CHARACTER_ENCODING = "UTF-8";
 
    /**
     * An instance of {@link Charset} for the charset specified in
     * {@link #APP_CHARACTER_ENCODING}
     */
    public static final Charset APP_CHARSET = Charset.forName(APP_CHARACTER_ENCODING);

    /**
     * Contains a base16 encoded secret key used by a symmetric cipher to
     * encrypt/decrypt PII information. Normally a AES-256 key. You can generate
     * the key by running the {@link GenerateAes256KeyCommand} in Blitzkrieg.
     * Default value is {@code null}.
     * <p/>
     * If value is not set, no encryption/decryption is performed for PII
     * information.
     *
     * @see PiiModule
     */
    public static final String PII_SECRET = "C8AA3C7B134B09DD43C0BC67801CE35A";

    /**
     * Retrieves a value associated with the {@code key} and converts it to the
     * type {@code T}. If the value is not present, a {@link RuntimeException}
     * is thrown.
     *
     * @param key
     *            configuration key
     * @param message
     *            error message part added the exception if the key is not found
     * @param type
     *            java class of type of value to retrieve.
     * @param <T>
     *            type of value to retrieve
     * @throws RuntimeException
     *             if the {@code key} is not present in the configuration.
     * @return value associated with the key converted to the type {@code T}
     */
    protected static <T> T newRequiredConfigValue(String key, String message, Class<T> type) {
        if (!props.containsKey(key))
            throw new RuntimeException("Fatal Error: config " + key + " not found in " + SECRETS_FILE + ": " + message);

        return get(props, key, null, type);
    }

    protected static <T> T newDefaultConfigValue(String key, T defaultValue, Class<T> type) {
        return get(props, key, defaultValue, type);
    }

    protected static <T> T get(Properties from, String key, T defaultValue, Class<T> type) {
        String value = from.getProperty(key);
        if (value != null && !value.isEmpty())
            return jsonMapper.convertValue(value, type);

        return defaultValue;
    }
}