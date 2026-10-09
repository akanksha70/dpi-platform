package com.akanksha.dpi;

import com.akanksha.dpi.classify.AppClassifier;
import com.akanksha.dpi.engine.AnalysisReport;
import com.akanksha.dpi.engine.DpiEngine;
import com.akanksha.dpi.engine.ReportFormatter;
import com.akanksha.dpi.engine.Rules;

import java.nio.file.Path;

public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }
        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        Rules rules = new Rules();
        int workers = 4;

        try {
            for (int i = 2; i < args.length; i++) {
                switch (args[i]) {
                    case "--block-ip" -> rules.blockIp(value(args, ++i, "--block-ip"));
                    case "--block-app" -> rules.blockApp(value(args, ++i, "--block-app"));
                    case "--block-domain" -> rules.blockDomain(value(args, ++i, "--block-domain"));
                    case "--workers" -> workers = Integer.parseInt(value(args, ++i, "--workers"));
                    default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
                }
            }
            AnalysisReport report = new DpiEngine(AppClassifier.loadDefault(), rules, workers)
                    .process(input, output);
            System.out.println(ReportFormatter.format(report));
            System.out.println("Output written to: " + output);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(2);
        }
    }

    private static String value(String[] args, int i, String option) {
        if (i >= args.length) throw new IllegalArgumentException(option + " needs a value");
        return args[i];
    }

    private static void printUsage() {
        System.out.println("""
                Usage: java -cp target/classes com.akanksha.dpi.Main <input.pcap> <output.pcap> [options]

                Options:
                  --block-ip <ip>        drop traffic from this source IP
                  --block-app <app>      drop an app, e.g. YouTube or "Twitter/X"
                  --block-domain <dom>   drop a domain and its subdomains
                  --workers <n>          number of worker threads (default 4)
                """);
    }
}