require 'sinatra'
require 'thin'
require 'sucker_punch'
require 'socket'
require 'netaddr'
require 'nmap/program'
require 'haml'
require 'rack-flash'

class Address
  def initialize
    @info = Socket.getifaddrs.find do |ifaddr|
      (ifaddr.flags & Socket::IFF_BROADCAST).nonzero? &&
        ifaddr.addr.afamily == Socket::AF_INET
    end
  end

  def start_ip_to_s
    @info.addr.ip_address.split('.')[0..2].join('.') + ".0".to_s
  end 

  def cidr_to_s
    NetAddr::CIDR.create('0.0.0.0/'+"#{@info.netmask.ip_address}").netmask
  end

end

class Scan
  include SuckerPunch::Job
  workers 4

  def initialize
    @filepath = "./tmp/scan.xml"
  end

  def ping_sweep(targets)
    Nmap::Program.scan do |nmap|
      nmap.ping = true
      nmap.targets = "#{targets}"
      nmap.verbose = true
      nmap.xml = @filepath
    end
  end
end

class Application < Sinatra::Base
  configure do
    set :title, "Asynchronus Sinatra"
    set :author, "Brenton Earl"
    set :server, 'thin'
    set :bind, '127.0.0.1'
    set :port, '3000'
    enable :inline_templates
    enable :sessions
    use Rack::Flash
  end

  get '/' do
    haml :index
  end

  post '/scan' do
    @address = Address.new
    @scan_target = @address.start_ip_to_s + @address.cidr_to_s
    @scanner = Scan.new
    @scanner.async.ping_sweep(@scan_target)
    flash[:notice] = "scan successful"
    redirect '/'
  end

end

__END__

@@layout
%html
  %head
    %title #{ settings.title }
  %body
    - %w[notice error warning alert info].each do |key|
      - if flash[key]
        %div{:id => key,:class => "flash"}= flash[key]

  = yield 

@@index
%p Testing Asynchronus Processes in Sinatra

%form{ :action => "/scan", :method => "post"}
  %input{:type => "submit", :value => "Run Ping sweep", :class => "button"}
