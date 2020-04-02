package fr.gouv.ssi.rommask.jcaparser.mask.filesystem;

/*-
 * #%L
 * Java Card RomMask Generator
 * %%
 * Copyright (C) 2020 National Cybersecurity Agency of France (ANSSI)
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

/**
 * Class which computes a flash package regarding the CHOUPI operating system
 *
 * @author Guillaume Bouffard
 */
public class FlashPackage {

    /**
     * Package AID
     */
    private byte[] aid;

    /**
     * Package minor version
     */
    private byte major_version;

    /**
     * Package major version
     */
    private byte minor_version;

    /**
     * CAP File
     */
    private byte[] cap;

    /**
     * Package name
     */
    private String name;

    /**
     * Class constructorFlash
     *
     * @param name
     * @param aid           package AID
     * @param major_version package major version
     * @param minor_version package minor version
     * @param cap           the associated CAP file
     */
    FlashPackage(String name, byte[] aid, byte major_version, byte minor_version, byte[] cap) {
        this.name = name;
        this.aid = aid;
        this.major_version = major_version;
        this.minor_version = minor_version;
        this.cap = cap;
    }

    /**
     * Gets package AID
     *
     * @return package AID
     */
    public byte[] getAID() {
        return aid;
    }

    /**
     * Sets package AID
     *
     * @param aid new package AID
     */
    public void setAID(byte[] aid) {
        this.aid = aid;
    }

    /**
     * Gets package major version
     *
     * @return package major version
     */
    public byte getMajor_version() {
        return major_version;
    }

    /**
     * Set package major version
     *
     * @param major_version package major version
     */
    public void setMajor_version(byte major_version) {
        this.major_version = major_version;
    }

    /**
     * Gets package minor version
     *
     * @return package minor version
     */
    public byte getMinor_version() {
        return minor_version;
    }

    /**
     * Sets package minor version
     *
     * @param minor_version package minor version
     */
    public void setMinor_version(byte minor_version) {
        this.minor_version = minor_version;
    }

    /**
     * Gets package CAP
     *
     * @return package CAP
     */
    public byte[] getCAP() {
        return cap;
    }

    /**
     * Sets package CAP
     *
     * @param cap package CAP
     */
    public void setCAP(byte[] cap) {
        this.cap = cap;
    }
}
