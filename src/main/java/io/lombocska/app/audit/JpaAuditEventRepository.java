package io.lombocska.app.audit;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Journal d'audit persistant. Sa simple présence active les listeners d'audit
 * d'Actuator : succès et échecs d'authentification, déconnexions, refus d'autorisation.
 * L'identifiant de session n'est jamais stocké.
 */
@Repository
public class JpaAuditEventRepository implements AuditEventRepository {

	private final AuditEventRecordRepository records;

	public JpaAuditEventRepository(AuditEventRecordRepository records) {
		this.records = records;
	}

	@Override
	@Transactional
	public void add(AuditEvent event) {
		Map<String, Object> data = new LinkedHashMap<>(event.getData());
		String remoteAddress = null;
		if (data.remove("details") instanceof WebAuthenticationDetails details) {
			remoteAddress = details.getRemoteAddress();
		}
		String detail = data.entrySet()
			.stream()
			.map((entry) -> entry.getKey() + "=" + entry.getValue())
			.collect(Collectors.joining("; "));
		this.records.save(new AuditEventRecord(event.getTimestamp(), event.getPrincipal(), event.getType(),
				remoteAddress, truncate(detail)));
	}

	@Override
	@Transactional(readOnly = true)
	public List<AuditEvent> find(String principal, Instant after, String type) {
		Specification<AuditEventRecord> spec = (root, query, cb) -> cb.conjunction();
		if (principal != null) {
			spec = spec.and((root, query, cb) -> cb.equal(root.get("principal"), principal));
		}
		if (after != null) {
			spec = spec.and((root, query, cb) -> cb.greaterThan(root.get("occurredAt"), after));
		}
		if (type != null) {
			spec = spec.and((root, query, cb) -> cb.equal(root.get("type"), type));
		}
		return this.records.findAll(spec, Sort.by("occurredAt"))
			.stream()
			.map((r) -> new AuditEvent(r.getOccurredAt(), r.getPrincipal(), r.getType(),
					Map.of("remoteAddress", String.valueOf(r.getRemoteAddress()), "detail",
							String.valueOf(r.getDetail()))))
			.toList();
	}

	private static String truncate(String value) {
		return (value.length() > 1000) ? value.substring(0, 1000) : value;
	}

}
