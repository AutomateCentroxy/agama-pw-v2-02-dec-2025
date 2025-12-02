package org.gluu.agama.login;

/**
 * Helper class for counter operations in Agama flows
 */
public class CounterHelper {
    
    /**
     * Increment a counter value by 1
     * @param currentValue the current counter value
     * @return the incremented value
     */
    public static int increment(int currentValue) {
        return currentValue + 1;
    }
    
    /**
     * Increment a counter value by a specific amount
     * @param currentValue the current counter value
     * @param incrementBy the amount to increment by
     * @return the incremented value
     */
    public static int incrementBy(int currentValue, int incrementBy) {
        return currentValue + incrementBy;
    }
    
    /**
     * Check if counter has reached a maximum value
     * @param currentValue the current counter value
     * @param maxValue the maximum allowed value
     * @return true if max is reached, false otherwise
     */
    public static boolean hasReachedMax(int currentValue, int maxValue) {
        return currentValue >= maxValue;
    }
}

