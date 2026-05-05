'use strict';

var test = require('tap').test;
var unzip = require('../');
var Entry = require('../lib/entry');

test("path traversal vulnerability (Zip Slip) sanitization", function (t) {
  var unzipParser = unzip.Parse();

  var maliciousPaths = [
    { input: "../../etc/passwd", expected: "././etc/passwd" },
    { input: "..\\..\\windows\\system32\\cmd.exe", expected: ".\\.\\windows\\system32\\cmd.exe" },
    { input: "folder/../../etc/passwd", expected: "folder/././etc/passwd" },
    { input: "deep/folder/../../../etc/passwd", expected: "deep/folder/./././etc/passwd" },
    { input: "some/valid/path/..", expected: "some/valid/path/." },
    { input: "..../etc/passwd", expected: "./etc/passwd" }, // Testing "...." replacing multiple dots
    { input: "/absolute/path/../../etc", expected: "/absolute/path/././etc" },
    { input: "C:\\absolute\\path\\..\\..\\etc", expected: "C:\\absolute\\path\\.\\.\\etc" },
    { input: "valid/path/file.txt", expected: "valid/path/file.txt" } // Sanity check for normal files
  ];

  maliciousPaths.forEach(function(testCase) {
    var entry = new Entry();
    entry.path = testCase.input;

    // Mock the minimal parsedEntity vars needed by `_prepareOutStream`
    var mockVars = {
      uncompressedSize: 10,
      flags: 0,
      versionsNeededToExtract: 20,
      compressedSize: 10,
      extra: {},
      compressionMethod: 0
    };

    // run the path sanitization logic
    unzipParser.unzipStream._prepareOutStream(mockVars, entry);

    t.equal(entry.path, testCase.expected, "Sanitized '" + testCase.input + "' to '" + testCase.expected + "'");
  });

  t.end();
});