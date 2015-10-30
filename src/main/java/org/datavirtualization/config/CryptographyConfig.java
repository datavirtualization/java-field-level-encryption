package org.datavirtualization.config;

import java.nio.charset.Charset;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.List;
import java.util.Properties;

import com.fasterxml.jackson.databind.ObjectMapper;

public class CryptographyConfig {
    /** The primary application secret used to check signatures */
    public static final String APP_SECRET = 
        newRequiredConfigValue("app.secret", "app secret not set in your properties file", 
            String.class);

    /** The properties file name. The file should be on the classpath. */
    private static final String       SECRETS_FILE = "classpath:properties/secrets.{0}.properties";

    private static final ObjectMapper jsonMapper = new ObjectMapper();

    protected static final Properties props = new Properties();

    static {
    //     loadPropsFrom(SECRETS_FILE, props);
        props.setProperty("app.secret","a1cc5e57cd469950c317c05625edc9dc");
    }

    /**
     * Loading a properties file for any environment will also load the
     * environment named with this token, and merge the actual environment down
     * on top of it. Properties files with no environment substitution token
     * will of course not be affected.
     */
    private static final String       TOKEN_COMMON = "common";

    /**
     * Load properties from the given filename into the given Properties
     * instance. The filename can include a {0} replacement token and if it
     * does, a "common" properties file will first be searched for and loaded.
     * Then the environment specific file will be merged on top of it (overrides
     * duplicated values).
     * 
     * @param filename
     *            The name of the properties file to load. Can include a {0}
     *            token which will be replaced with the environment name. See
     *            {@link EnvironmentResolver}.
     * @param into
     *            The properties instance to load into. It is allowed for this
     *            instance to already contain other properties. In this case,
     *            any new loaded properties will override those pre-existing
     *            ones.
     */
    /*
    protected static void loadPropsFrom(String filename, Properties into) {
        try {
            String commonFilename = MessageFormat.format(filename, TOKEN_COMMON);
            if (!commonFilename.equals(filename)) {
                Resource commonResource = ApplicationEnvironmentUtil.getResource(commonFilename);
                if ((commonResource != null) && commonResource.exists()) {
                    into.load(commonResource.getInputStream());
                }
            }

            Resource resource = ApplicationEnvironmentUtil.getResource(filename);
            if (resource == null || !resource.exists()) {
                throw new RuntimeException("Could not find the " + filename + " file");
            }
            into.load(resource.getInputStream());
        }
        catch (IOException ioe) {
            throw new RuntimeException(filename + " file found but failed to load");
        }
    }

    protected static void loadPropsFrom(List<String> filenames, Properties into) {
        for (String filename : filenames) {
            loadPropsFrom(filename, into);
        }
    }
    */


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
    public static final String APP_CHARACTER_ENCODING = 
        newDefaultConfigValue("app.character.encoding", "UTF-8", String.class).replace("\"", "").replace("\'", "");

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
    public static final String PII_SECRET = newDefaultConfigValue("app.pii.secret", null, String.class);


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