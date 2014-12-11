require 'rubygems'
require 'sinatra/base'
require 'haml'
require 'thin'
require 'sucker_punch'
require 'socket'
require 'netaddr'
require 'nmap/program'
require 'nmap/xml'


# Provides IP Adress information for Port Scanner
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


# Runs Port Scans and Parses xml file
class Scan

  include SuckerPunch::Job
  workers 2 

  def ping_sweep(targets)
    nmap = Nmap::Program.find
    nmap.sudo_task(Nmap::Task.new { |nmap|
      nmap.ping = true
      nmap.scan_delay = "0.5"      
      nmap.targets = targets
      nmap.verbose = true
      nmap.xml = './tmp/scan.xml'
    })
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
  end

  get '/' do
    haml :index
  end

  get '/scan' do
    haml :scan
  end

  get '/hosts' do
    @parser = Nmap::XML.new('./tmp/scan.xml')
    haml :hosts
  end

  post '/scan' do
    @address = Address.new
    @scan_target = @address.start_ip_to_s + @address.cidr_to_s
    @scanner = Scan.new
    @scanner.async.ping_sweep(@scan_target)
    redirect '/'
  end

end

__END__

@@layout
!!!
%html
  %head
    %title #{ settings.title }
  %body

    = yield 

    %script(src="/right.js")
    %script(src="/right-tabs.js")

@@index
%h2 #{ settings.title }
%small App created by #{ settings.author }
%p Testing Asynchronus Processes in Sinatra


%ul.rui-tabs
  %ul
    %li
      %a#tab-1(href='/scan') Scan
    %li
      %a#tab-2(href='/hosts') Hosts

@@scan
%form#scan{ :action => "/scan", :method => "post"}
  %input{:type => "submit", :value => "Run Ping sweep", :class => "button"}

@@hosts
%table
  %tr
    %td Address
    %td MAC
  - @parser.each_up_host do |host|
    %tr
      %td #{host.ip}
      %td #{host.mac}

