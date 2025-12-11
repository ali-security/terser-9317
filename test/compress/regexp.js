regexp_simple: {
    input: {
        /rx/ig
    }
    expect_exact: "/rx/gi;"
}

regexp_slashes: {
    input: {
        /\\\/rx\/\\/ig
    }
    expect_exact: "/\\\\\\/rx\\/\\\\/gi;"
}

regexp_1: {
    options = {
    }
    input: {
        console.log(JSON.stringify("COMPASS? Overpass.".match(/([Sap]+)/ig)));
    }
    expect: {
        console.log(JSON.stringify("COMPASS? Overpass.".match(/([Sap]+)/gi)));
    }
    expect_stdout: '["PASS","pass"]'
}

regexp_2: {
    options = {
        evaluate: true,
        unsafe: true,
    }
    input: {
        // Pattern with + quantifier is no longer optimized (CVE-2022-25858 fix)
        console.log(JSON.stringify("COMPASS? Overpass.".match(new RegExp("([Sap]+)", "ig"))));
    }
    expect: {
        console.log(JSON.stringify("COMPASS? Overpass.".match(RegExp("([Sap]+)","ig"))));
    }
    expect_stdout: '["PASS","pass"]'
}

issue_CVE_2022_25858_1: {
    options = {
        evaluate: true,
        unsafe: true,
    }
    input: {
        // ReDoS-prone regex literal should NOT be evaluated
        console.log(/(b+)+$/.test("b]"));
    }
    expect: {
        // Pattern should remain unevaluated to prevent ReDoS
        console.log(/(b+)+$/.test("b]"));
    }
    expect_stdout: "false"
}

issue_CVE_2022_25858_2: {
    options = {
        evaluate: true,
        unsafe: true,
    }
    input: {
        // ReDoS-prone RegExp constructor should NOT be optimized
        console.log(new RegExp("(a+)+$").test("a"));
    }
    expect: {
        // Pattern should remain as constructor call to prevent ReDoS
        console.log(RegExp("(a+)+$").test("a"));
    }
    expect_stdout: "true"
}

issue_CVE_2022_25858_3: {
    options = {
        evaluate: true,
        unsafe: true,
    }
    input: {
        // Safe regex literal SHOULD still be evaluated
        console.log(/^foo$/.test("foo"));
    }
    expect: {
        console.log(true);
    }
    expect_stdout: "true"
}

issue_CVE_2022_25858_4: {
    options = {
        evaluate: true,
        unsafe: true,
    }
    input: {
        // Safe RegExp constructor SHOULD still be optimized to literal
        var re = new RegExp("foo");
    }
    expect: {
        var re = /foo/;
    }
}
