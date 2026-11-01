package io.lombocska.app.security.bruteforce;

import java.time.Instant;

public record AccountLockedEvent(String email, Instant lockedUntil, long failedAttempts) {
}
