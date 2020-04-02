package fr.gouv.ssi.rommask.jcaparser.util;

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
 * Templated generic triplet class
 *
 * @param <X> type of the first element
 * @param <Y> type of the second element
 * @param <Z> type of the third element
 * @author Guillame Bouffard
 */
public class Triplet<X, Y, Z> {

    /**
     * First element
     */
    private X first;

    /**
     * Second element
     */
    private Y second;

    /**
     * Third element
     */
    private Z third;

    /**
     * Default constructor
     *
     * @param first
     * @param second
     * @param third
     */
    public Triplet(X first, Y second, Z third) {
        this.first = first;
        this.second = second;
        this.third = third;
    }

    /**
     * Gets first value
     *
     * @return first value
     */
    public X getFirst() {
        return first;
    }

    /**
     * Set first value
     *
     * @param first new first value
     */
    public void setFirst(X first) {
        this.first = first;
    }

    /**
     * Gets second value
     *
     * @return second value
     */
    public Y getSecond() {
        return second;
    }

    /**
     * Set second value
     *
     * @param second new first value
     */
    public void setSecond(Y second) {
        this.second = second;
    }

    /**
     * Gets third value
     *
     * @return third value
     */
    public Z getThird() {
        return third;
    }

    /**
     * Set third value
     *
     * @param third new first value
     */
    public void setThird(Z third) {
        this.third = third;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + this.first.hashCode();
        result = prime * result + this.second.hashCode();
        result = prime * result + this.third.hashCode();
        return result;
    }


    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        final Triplet other = (Triplet) obj;

        if (this.first == null) {
            if (other.first != null) {
                return false;
            }
        } else if (!this.first.equals(other.first)) {
            return false;
        }
        if (this.second == null) {
            if (other.second != null) {
                return false;
            }
        } else if (!this.second.equals(other.second)) {
            return false;
        }
        if (this.third == null) {
            return other.third == null;
        } else return this.third.equals(other.third);
    }
}
