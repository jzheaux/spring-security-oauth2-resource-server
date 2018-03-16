package org.springframework.messages;

import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.validation.constraints.NotNull;

/**
 * @author Rob Winch
 */
@Entity
public class Message {
	@SequenceGenerator(initialValue=2, name="seq")
	@GeneratedValue(generator = "seq")
	@Id
	private Long id;

	@NotEmpty(message = "Text is required")
	private String text;

	public Message() {}

	public Message(String text) {
		this.text = text;
	}

	public Long getId() {
		return this.id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getText() {
		return this.text;
	}

	public void setText(String text) {
		this.text = text;
	}
}
