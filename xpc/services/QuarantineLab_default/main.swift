import Foundation

let listener = NSXPCListener.service()
let delegate = QuarantineLabServiceDelegate()
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
