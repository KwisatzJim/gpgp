//
//  GPGPApp.swift
//  GPGP
//
//  Created by Jim Kelley on 10/25/26.
//

import SwiftUI

@main
struct GPGPApp: App {
    var body: some Scene {
        WindowGroup("GPGP") {
            ContentView()
        }
        .defaultSize(width: 860, height: 740)
        .windowResizability(.contentMinSize)
    }
}
