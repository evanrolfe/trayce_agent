file_name = "test_output.txt"
i = 0

while true
  system("[ -e #{file_name} ] && rm #{file_name}")
  system("make test > #{file_name}")

  output = File.read(file_name)

  if output.include?("FAIL")
    puts "#{i}.FAIL!"
    break
  else
    puts "#{i}. PASS"
  end

  i += 1
end
