import Foundation

let listener = NSXPCListener.service()
let delegate = ProbeServiceSessionDelegate()
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
