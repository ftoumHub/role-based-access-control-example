package io.lombocska.app.audit;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface AuditEventRecordRepository
		extends JpaRepository<AuditEventRecord, Long>, JpaSpecificationExecutor<AuditEventRecord> {

}
