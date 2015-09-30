package org.datavirtualization.config.CryptographyConfig;

import java.nio.charset.Charset;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.List;
import java.util.Properties;

import com.fasterxml.jackson.databind.ObjectMapper;

public class CryptographyConfig {
    private static final ObjectMapper jsonMapper = new ObjectMapper();

    protected static final Properties props = new Properties();

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
    public static final String APP_CHARACTER_ENCODING = newDefaultConfigValue("app.character.encoding", "UTF-8", String.class).replace("\"", "").replace("\'", "");

    /**
     * An instance of {@link Charset} for the charset specified in
     * {@link #APP_CHARACTER_ENCODING}
     */
    public static final Charset APP_CHARSET = Charset.forName(APP_CHARACTER_ENCODING);

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