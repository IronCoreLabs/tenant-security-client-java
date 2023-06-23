package com.ironcorelabs.tenantsecurity.utils;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Utility functions for working with CompletableFutures.
 */
public final class CompletableFutures {
  /**
   * Convert a List of CompletableFutures into a CompletableFuture of a List.
   */
  public static <T> CompletableFuture<List<T>> sequence(List<CompletableFuture<T>> futures) {
    return CompletableFuture.allOf(futures.toArray(new CompletableFuture[futures.size()]))
        .thenApplyAsync(
            v -> futures.stream().map(future -> future.join()).collect(Collectors.<T>toList()));
  }

  /**
   * Try to run the given function, placing the value in a CompletableFuture. Exceptions will be
   * caught in a failed CompletableFuture, fatal Throwables should still bubble up.
   *
   * @param function function (that may throw) to run and capture the value of.
   * @return CompleteableFuture either completed with the resulting value or failed with an
   *         exception.
   */
  public static <T> CompletableFuture<T> tryCatchNonFatal(CompletableFutureSupplier<T> function) {
    Objects.requireNonNull(function);

    try {
      return CompletableFuture.completedFuture(function.get());
    } catch (Exception e) {
      CompletableFuture<T> thisShouldBeStatic = new CompletableFuture<>();
      thisShouldBeStatic.completeExceptionally(e);
      return thisShouldBeStatic;
    }
  }
}
