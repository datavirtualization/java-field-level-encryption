package org.datavirtualization.crypto.test;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;

import static org.datavirtualization.util.CryptographyUtil.piiCodec;

/**
 * This is a String that contains PII. If PII encryption is enabled, this will
 * get encrypted at the appropriate times (e.g.- storage in the database) and
 * used as clear text at the appropriate times (e.g.- output to the client).
 */
public class PiiString implements Serializable {
    private static final long serialVersionUID = 6651093268482941313L;

    protected final String    value;

    @JsonIgnore
    private transient String  clearTextValue;

    public PiiString(String value) {
        this(value, true);
    }

    protected PiiString(String value, boolean checkValueCipherText) {
        Preconditions.checkNotNull(value, "value may not be null");
        if (checkValueCipherText)
            piiCodec.assertCipherText(value);
        this.value = value;
    }

    /**
     * Creates a new instance of {@link PiiString} or null if value is null
     * string. Does not check whether value is an encrypted pii or not. Used by
     * the code where one PII needs to be constructed from another.
     * 
     * @see CryptographyConfig#PII_SECRET
     * @param value
     *            that represents a PII
     * @return an instance of {@link PiiString}
     */
    public static PiiString createUnsafely(String value) {
        return (value == null) ? null : new PiiString(value, false);
    }

    /**
     * Creates a new instance of {@link PiiString} or null if value is null
     * string. The value provided is considered clear text and if PII encryption
     * is enabled, the value will be encrypted as cipher text.
     * 
     * @param value
     *            a PII as clear text
     * 
     * @see CryptographyConfig#PII_SECRET
     * @return an instance of {@link PiiString}
     */
    @JsonIgnore
    public static PiiString fromClearText(String value) {
        if (value == null)
            return null;

        PiiString piiString = new PiiString(piiCodec.encrypt(value), false);
        piiString.clearTextValue = value;
        return piiString;
    }

    /**
     * @see CryptographyConfig#PII_SECRET
     * @return the value as clear text. The method returns the same string value
     *         as {@link #getValue()} if PII encryption is not enabled.
     */
    public String getClearTextValue() {
        if (clearTextValue == null) {
            clearTextValue = piiCodec.decrypt(getValue());
        }

        return clearTextValue;
    }

    /**
     * @return the value stored. If PII encryption enabled, the value will be an
     *         encrypted PII.
     */
    @JsonIgnore
    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;

        if (o instanceof PiiString) {
            PiiString that = (PiiString) o;
            return Objects.equal(this.getValue(), that.getValue());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }
}
