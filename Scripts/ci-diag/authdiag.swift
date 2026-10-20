import Foundation
import Security
var auth: AuthorizationRef?
precondition(AuthorizationCreate(nil, nil, [], &auth) == errAuthorizationSuccess)
var ext = AuthorizationExternalForm()
precondition(AuthorizationMakeExternalForm(auth!, &ext) == errAuthorizationSuccess)
var auth2: AuthorizationRef?
precondition(AuthorizationCreateFromExternalForm(&ext, &auth2) == errAuthorizationSuccess)
let name = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "com.ehsanazish.nick.modify-protection"
let status: OSStatus = name.withCString { n in
    var item = AuthorizationItem(name: n, valueLength: 0, value: nil, flags: 0)
    return withUnsafeMutablePointer(to: &item) { p in
        var rights = AuthorizationRights(count: 1, items: p)
        return AuthorizationCopyRights(auth2!, &rights, nil, [], nil)
    }
}
print("uid=\(getuid()) right=\(name) AuthorizationCopyRights(flags=[]) -> \(status) (\(status == errAuthorizationSuccess ? "GRANTED" : "refused"))")
