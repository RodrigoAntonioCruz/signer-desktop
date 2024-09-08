package com.signer.exception;

import org.apache.commons.lang3.exception.ExceptionUtils;

import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;
import static org.apache.commons.lang3.ObjectUtils.isNotEmpty;

public final class ExceptionResolver {

	private static final String UNAVAILABLE_STACK_TRACE= "StackTrace Indisponivel";
	
	private ExceptionResolver() {
	}

	public static String getRootException(Throwable ex) {
		return String.format("%s in class: %s Line: %s", ExceptionUtils.getRootCauseMessage(ex),
				ExceptionUtils.getRootCause(ex).getStackTrace()[0].getClassName(),
				ExceptionUtils.getRootCause(ex).getStackTrace()[0].getLineNumber());
	}

    public static String getCauseException(Throwable exception){
        var rootCause = defaultIfNull(ExceptionUtils.getRootCause(exception), exception);

        if(isNotEmpty(rootCause.getStackTrace())){
            return buildMessage(rootCause);
        }

        if(isNotEmpty(exception.getStackTrace())){
            return buildMessage(exception);
        }

        return String.format("%s in class: %s Line: %d", exception, UNAVAILABLE_STACK_TRACE  , 0);
    }

    private static String buildMessage(Throwable exception) {
        return String.format("%s in class: %s Line: %d", exception, exception.getStackTrace()[0].getClassName(), exception.getStackTrace()[0].getLineNumber());
    }
}
