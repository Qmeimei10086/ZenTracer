function log(text) {
    var packet = {
        'cmd': 'log',
        'data': text
    };
    send("ZenTracer:::" + JSON.stringify(packet))
}

function detailed_log(text) {
    var packet = {
        'cmd': 'detailed_log', 
        'data': text
    };
    send("ZenTracer:::" + JSON.stringify(packet))
}

function enter(tid, tname, cls, method, args, call_stack) {
    var packet = {
        'cmd': 'enter',
        'data': [tid, tname, cls, method, args, call_stack]
    };
    send("ZenTracer:::" + JSON.stringify(packet))
}

function exit(tid, retval) {
    var packet = {
        'cmd': 'exit',
        'data': [tid, retval]
    };
    send("ZenTracer:::" + JSON.stringify(packet))
}

function getTid() {
    var Thread = Java.use("java.lang.Thread")
    return Thread.currentThread().getId();
}

function getTName() {
    var Thread = Java.use("java.lang.Thread")
    return Thread.currentThread().getName();
}

function getCallStack() {
    try {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
    } catch (e) {
        return "Unable to get call stack: " + e;
    }
}

function hasOwnProperty(obj, name) {
    try {
        return obj.hasOwnProperty(name) || name in obj;
    } catch (e) {
        return obj.hasOwnProperty(name);
    }
}

function getHandle(object) {
    if (hasOwnProperty(object, '$handle')) {
        if (object.$handle != undefined) {
            return object.$handle;
        }
    }
    if (hasOwnProperty(object, '$h')) {
        if (object.$h != undefined) {
            return object.$h;
        }
    }
    return null;
}

function inspectObject(obj) {
    var output = "";
    var isInstance = false;
    var obj_class = null;
    
    if (getHandle(obj) === null) {
        obj_class = obj.class;
    } else {
        var Class = Java.use("java.lang.Class");
        obj_class = Java.cast(obj.getClass(), Class);
        isInstance = true;
    }
    
    output = output.concat("Inspecting Fields: => ", isInstance ? "Instance" : "Static", " => ", obj_class.toString());
    output = output.concat("\n");
    
    try {
        var fields = obj_class.getDeclaredFields();
        for (var i in fields) {
            if (isInstance || Boolean(fields[i].toString().indexOf("static ") >= 0)) {
                var className = obj_class.toString().trim().split(" ")[1];
                var fieldName = fields[i].toString().split(className.concat(".")).pop();
                var fieldType = fields[i].toString().split(" ").slice(-2)[0];
                var fieldValue = undefined;
                
                try {
                    if (!(obj[fieldName] === undefined)) {
                        fieldValue = obj[fieldName].value;
                    }
                    output = output.concat(fieldType + " \t" + fieldName + " => " + fieldValue);
                    output = output.concat("\n");
                } catch (e) {
                    output = output.concat(fieldType + " \t" + fieldName + " => [Access denied]");
                    output = output.concat("\n");
                }
            }
        }
    } catch (e) {
        output = output.concat("Failed to inspect object: " + e);
    }
    
    return output;
}

function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf(".");
    if (delim === -1) return;
    
    var targetClass = targetClassMethod.slice(0, delim)
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
    
    try {
        var hook = Java.use(targetClass);
        if (!hook[targetMethod]) {
            log("Method not found: " + targetClassMethod);
            return;
        }
        
        var overloadCount = hook[targetMethod].overloads.length;
        log("Tracing Method: " + targetClassMethod + " [" + overloadCount + " overload(s)]");
        
        for (var i = 0; i < overloadCount; i++) {
            hook[targetMethod].overloads[i].implementation = function () {
                var startTime = Date.now();
                var tid = getTid();
                var tName = getTName();
                var callStack = getCallStack();
                
                // Build arguments string
                var args = [];
                for (var j = 0; j < arguments.length; j++) {
                    try {
                        args[j] = JSON.stringify(arguments[j]) || String(arguments[j]);
                    } catch (e) {
                        args[j] = "[Unserializable: " + typeof arguments[j] + "]";
                    }
                }
                
                // Send enter event
                enter(tid, tName, targetClass, targetMethod, args, callStack);
                
                // Detailed logging
                var detailedOutput = "=== Entered " + targetClassMethod + " ===\n";
                detailedOutput += "Thread: " + tid + " - " + tName + "\n";
                
                if (args.length > 0) {
                    detailedOutput += "Arguments:\n";
                    for (var j = 0; j < args.length; j++) {
                        detailedOutput += "  arg[" + j + "]: " + args[j] + "\n";
                    }
                }
                
                // Inspect object if it's an instance method
                if (this != null && getHandle(this) !== null) {
                    try {
                        detailedOutput += "Object fields:\n";
                        detailedOutput += inspectObject(this);
                    } catch (e) {
                        detailedOutput += "Object inspection failed: " + e + "\n";
                    }
                }
                
                detailedOutput += "Call Stack:\n" + callStack + "\n";
                detailed_log(detailedOutput);
                
                try {
                    var retval = this[targetMethod].apply(this, arguments);
                    var executionTime = Date.now() - startTime;
                    
                    // Send exit event
                    exit(tid, JSON.stringify(retval) || String(retval));
                    
                    // Detailed exit logging
                    var exitOutput = "=== Exited " + targetClassMethod + " ===\n";
                    exitOutput += "Execution time: " + executionTime + "ms\n";
                    exitOutput += "Return value: " + (JSON.stringify(retval) || String(retval)) + "\n";
                    detailed_log(exitOutput);
                    
                    return retval;
                } catch (e) {
                    var executionTime = Date.now() - startTime;
                    exit(tid, "[Exception: " + e + "]");
                    
                    var errorOutput = "=== Exception in " + targetClassMethod + " ===\n";
                    errorOutput += "Execution time: " + executionTime + "ms\n";
                    errorOutput += "Exception: " + e + "\n";
                    errorOutput += "Stack: " + e.stack + "\n";
                    detailed_log(errorOutput);
                    
                    throw e;
                }
            }
        }
    } catch (e) {
        log("Failed to trace method " + targetClassMethod + ": " + e);
    }
}

function traceClass(clsname) {
    try {
        log("Tracing class: " + clsname);
        var hook = Java.use(clsname);
        var methods = hook.class.getDeclaredMethods();
        var constructors = hook.class.getDeclaredConstructors();
        
        // Trace constructors
        if (constructors.length > 0) {
            constructors.forEach(function (constructor) {
                try {
                    traceMethod(clsname + ".$init");
                } catch (e) {
                    log("Failed to trace constructor for " + clsname + ": " + e);
                }
            });
        }
        
        // Trace methods
        methods.forEach(function (method) {
            try {
                var methodName = method.getName();
                traceMethod(clsname + "." + methodName);
            } catch (e) {
                log("Failed to trace method " + method.getName() + " in " + clsname + ": " + e);
            }
        });
        
    } catch (e) {
        log("Failed to trace class '" + clsname + "': " + e);
    }
}

function match(ex, text) {
    if (ex[1] == ':') {
        var mode = ex[0];
        if (mode == 'E') {
            ex = ex.substr(2, ex.length - 2);
            return ex == text;
        } else if (mode == 'M') {
            ex = ex.substr(2, ex.length - 2);
        } else {
            log("Unknown match mode: " + mode + ", current support M(match) and E(equal)");
            return false;
        }
    }
    
    try {
        return text.match(ex);
    } catch (e) {
        log("Regex match error: " + e + " for pattern: " + ex);
        return false;
    }
}

// Enhanced class enumeration with better filtering
function enumerateAndTraceClasses() {
    var matchRegEx = {MATCHREGEX};
    var blackRegEx = {BLACKREGEX};
    
    if (matchRegEx.length === 0) {
        log("No match patterns specified. Please configure Match RegEx.");
        return;
    }
    
    log('Starting enhanced class enumeration...');
    var tracedClasses = 0;
    
    Java.enumerateLoadedClasses({
        onMatch: function (aClass) {
            for (var index in matchRegEx) {
                if (match(matchRegEx[index], aClass)) {
                    var is_black = false;
                    for (var i in blackRegEx) {
                        if (match(blackRegEx[i], aClass)) {
                            is_black = true;
                            log("Class '" + aClass + "' blacklisted by '" + blackRegEx[i] + "'");
                            break;
                        }
                    }
                    if (!is_black) {
                        log("Class '" + aClass + "' matched by '" + matchRegEx[index] + "' - tracing...");
                        try {
                            traceClass(aClass);
                            tracedClasses++;
                        } catch (e) {
                            log("Failed to trace class '" + aClass + "': " + e);
                        }
                    }
                    break; // Stop checking other match patterns once matched
                }
            }
        },
        onComplete: function () {
            log("Class enumeration complete. Traced " + tracedClasses + " classes.");
        }
    });
}

// Main execution
if (Java.available) {
    Java.perform(function () {
        log('Enhanced ZenTracer Started...');
        log('Features: Method tracing, call stack, field inspection, better argument handling');
        
        enumerateAndTraceClasses();
    });
} else {
    log("Java not available - waiting...");
    Java.performNow(function() {
        log('Enhanced ZenTracer Started (delayed)...');
        enumerateAndTraceClasses();
    });
}