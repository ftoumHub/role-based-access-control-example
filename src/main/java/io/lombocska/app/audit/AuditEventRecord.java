package io.lombocska.app.audit;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "audit_event")
public class AuditEventRecord {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "occurred_at", nullable = false)
	private Instant occurredAt;

	@Column(name = "principal", length = 191)
	private String principal;

	@Column(name = "type", length = 64, nullable = false)
	private String type;

	@Column(name = "remote_address", length = 64)
	private String remoteAddress;

	@Column(name = "detail", length = 1000)
	private String detail;

	protected AuditEventRecord() {
	}

	public AuditEventRecord(Instant occurredAt, String principal, String type, String remoteAddress, String detail) {
		this.occurredAt = occurredAt;
		this.principal = principal;
		this.type = type;
		this.remoteAddress = remoteAddress;
		this.detail = detail;
	}

	public Long getId() {
		return this.id;
	}

	public Instant getOccurredAt() {
		return this.occurredAt;
	}

	public String getPrincipal() {
		return this.principal;
	}

	public String getType() {
		return this.type;
	}

	public String getRemoteAddress() {
		return this.remoteAddress;
	}

	public String getDetail() {
		return this.detail;
	}

}
