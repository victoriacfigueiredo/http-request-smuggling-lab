require 'webrick'

backend = WEBrick::HTTPServer.new(Port: 8001)

backend.mount_proc '/' do |req, res|
  puts "\nServidor Recebeu:"
  puts req.request_line
  puts "Method: #{req.request_method}"
  puts "Path: #{req.path}"
  puts "Headers:"
  req.header.each do |k, v|
    puts "#{k}: #{v.inspect}"
  end
  puts "Body:"
  puts req.body.inspect

  res.status = 200
  res['Content-Type'] = 'text/plain'
  res.body = "Resposta do servidorn"
end

trap('INT') { backend.shutdown }
backend.start