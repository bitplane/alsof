# README for AI agents

VERY IMPORTANT INFO FOR LLMS

1. Follow the Zen of Python.
2. I'm using `black` and `isort` to format, so try to align formatting.
3. Pay attention to the imports, don't miss any out.
4. The project is for Python 3.10+, so no old fashioned type hints.
5. Complexity is the enemy of maintainability.
6. If you're given a huge patch at the start of the project, it's an export
   and probably has weeks of dev time squished into one commit.
7. Pay attention to line length

## NOTES ON LINE LENGTH

```
log.debug(
    "When you have a long line, it's okay to split it like this. "
    "Do this when necessary, rather than have enormous lines. "
    "and remember the trailing space on the end of split lines."
)
```

## IMPORTANT NOTES ON EXCEPTION HANDLING

I'm talking to you, Gemini.

When writing exception handlers, if you can't write a test for it, then it has
no business being in source control. When the logic is wrong, the user gets an
exception. This is what they deserve, they fucking earned it.

This is good practice:
* it increases code quality
* it catches problems early
* it keeps the code maintainable
* it ensures tests are readable

## IMPORTANT NOTES ON NAMES

Names are important. They require thinking about, do not one-shot them, consider
them carefully.

Use the context of the namespace to reduce the size of all names. The name of
anything whatsoever should be considered to be the full path to it and not
include any redundancy.

`package.subpackage.class.method.variable` should not repeat itself.

So for example, if the full path to a method is:

`utils.parser.PDFFile.open`

Then `pdf_file_path: Path` is a stupid name for a parameter. We know it's a
Path by the type hint, we know it's a PDF File.

I don't want to see you writing shit like:

`utility_libraries.file_parsers.PDFFileParser.open_pdf_file(pdf_file_name)`

Okay? It boils my piss.

## IMPORTANT NOTES ON COMPLEXITY

Every branch must be justified. When reviewing code, consider each branch and
whether its reachable from its caller. Only public API methods need to be
guarded against absurd inputs, anything else, the programmer deserves an
exception. If it makes them cry, then good.


## IMPORTANT NOTES ON TESTING

* tests are pytest style, functions
* one case per test - do not use parameterize
* do not heavily use mocks, or you failed and writing code
* each test should look something like this:

```
def test_horse_legless():
    """When the horse has no legs, it should not move"""
    silver = Horse()
    silver.legs = []
    expected = silver.position

    silver.gallop(direction=NORTH, time=100)
    actual = silver.position

    assert not legs, 'legs should not grow back'
    assert actual == expected
```

### explanation

* tests have a good name
* tests should try to be interesting

They look like:

* the setup steps
* then a gap of one line
* then the thing you're testing
* then a gap of one line
* then some asserts comparing expected with actual
* put more specific asserts before less specific ones, so early-failures
  highlight problems.

### reasons

* tests are executable documentation, they should be illustrative
* tests are be readable at a glance
* tests are be isolated
* tests are be varied
* tests provide insight
* tests provide useful data for testers
