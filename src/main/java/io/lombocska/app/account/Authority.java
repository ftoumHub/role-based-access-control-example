package io.lombocska.app.account;

import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "authority")
public class Authority {

	@Id
	@Column(name = "name", length = 50)
	private String name;

	protected Authority() {
	}

	public Authority(String name) {
		this.name = name;
	}

	public String getName() {
		return this.name;
	}

	@Override
	public boolean equals(Object o) {
		return this == o || (o instanceof Authority other && Objects.equals(this.name, other.name));
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(this.name);
	}

}
