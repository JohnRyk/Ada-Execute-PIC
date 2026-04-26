import pefile

def extract_sections_to_bin(pe_file_path, output_bin_path):
    try:
        # Load the PE
        pe = pefile.PE(pe_file_path)
        
        # open file
        with open(output_bin_path, 'wb') as output_file:
            # Walk all sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8').strip('\x00')
                
                # check if it is .text or .rdata
                if section_name in ('.text', '.rdata'):
                    print(f"Found section: {section_name}")
                    print(f"Virtual Address: 0x{section.VirtualAddress:08X}")
                    print(f"Size of Raw Data: 0x{section.SizeOfRawData:08X}")
                    
                    # Get the raw data of the sections and write it to the file
                    data = section.get_data().rstrip(b'\x00')
                    output_file.write(data)
            
            print(f"Successfully wrote .text and .rdata sections to {output_bin_path}")
    
    except pefile.PEFormatError as e:
        print(f"PEFormatError: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # make sure to close the PE file
        if 'pe' in locals():
            pe.close()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python extract_sections.py <input_exe_file> <output_bin_file>")
        sys.exit(1)
    
    input_exe = sys.argv[1]
    output_bin = sys.argv[2]
    
    extract_sections_to_bin(input_exe, output_bin)
