require 'webrick'
require 'webrick/httpproxy'

proxy = WEBrick::HTTPProxyServer.new(
  Port: 8002,
  ProxyContentHandler: Proc.new do |req, res|
    puts "\nProxy Recebeu:"
    puts req.request_line
    req.header.each do |k, v|
      puts "#{k}: #{v.inspect}"
    end
  end
)

trap('INT') { proxy.shutdown }
proxy.start