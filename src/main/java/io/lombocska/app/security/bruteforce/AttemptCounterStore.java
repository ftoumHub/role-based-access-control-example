package io.lombocska.app.security.bruteforce;

import java.time.Duration;

/**
 * Port de stockage des compteurs d'échecs. Chaque compteur expire {@code window} après
 * son premier incrément (fenêtre fixe).
 */
public interface AttemptCounterStore {

	long increment(String key, Duration window);

	long get(String key);

	void reset(String key);

}
