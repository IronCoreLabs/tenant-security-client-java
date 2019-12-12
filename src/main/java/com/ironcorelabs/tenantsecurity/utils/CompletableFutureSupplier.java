package com.ironcorelabs.tenantsecurity.utils;

/**
 * This is similar to the Java Supplier function type. It has a checked
 * exception on it to allow it to be used in lambda expressions for
 * CompletableFuture helpers.
 * 
 * https://github.com/jasongoodwin/better-java-monads
 * 
 * @param <T>
 */

public interface CompletableFutureSupplier<T>{
    T get() throws Exception;
}