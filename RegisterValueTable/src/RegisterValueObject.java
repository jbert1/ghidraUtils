package registervaluetable;

import ghidra.program.model.lang.Register;

/**
 * Object that holds a Register and associated Long value
 */
public class RegisterValueObject {
	
	private Register mRegister;
	private Long mValue;
	
	public RegisterValueObject(Register register, Long value) {
		mRegister = register;
		mValue = value;
	}

	public Register getRegister() {
		return mRegister;
	}

	public Long getValue() {
		return mValue;
	}

	public void setRegister(Register register) {
		mRegister = register;
	}

	public void setValue(Long value) {
		mValue = value;
	}
}
