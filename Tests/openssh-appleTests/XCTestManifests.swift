import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(openssh_appleTests.allTests),
    ]
}
#endif
