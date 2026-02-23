import pickle

input_file = 'gradient_boosting_model.pkl'
output_file = 'gradient_boosting_model_fixed.pkl'

print(f"Loading model from '{input_file}'...")

with open(input_file, 'rb') as model_file:
    try:
        loaded_model = pickle.load(model_file)
        print("Model loaded successfully with default settings.")
    except Exception as e:
        print(f"Default load failed: {e}")
        print("Trying with encoding='latin1'...")
        model_file.seek(0)
        try:
            loaded_model = pickle.load(model_file, encoding='latin1')
            print("Model loaded successfully with latin1 encoding.")
        except Exception as e2:
            print(f"Failed to load model even with latin1: {e2}")
            exit(1)

# Re-save with highest protocol for maximum compatibility
print(f"\nRe-saving model to '{output_file}' with highest pickle protocol...")
with open(output_file, 'wb') as new_file:
    pickle.dump(loaded_model, new_file, protocol=pickle.HIGHEST_PROTOCOL)

print("Model re-saved successfully!")
print(f"Use '{output_file}' in your Flask app for best compatibility.")



# import pickle

# with open('gradient_boosting_model.pkl', 'rb') as model_file:
#     try:
#         loaded_model = pickle.load(model_file)
#     except Exception as e:
#         print(f"Error loading pickle file: {e}")
#         # Attempt to load with a different encoding
#         try:
#             model_file.seek(0)
#             loaded_model = pickle.load(model_file, encoding='latin1')
#             print("Successfully loaded pickle file with latin1 encoding.")
#         except Exception as e2:
#             print(f"Error loading pickle file with latin1 encoding: {e2}")
#             exit()


# with open('gradient_boosting_model_new.pkl', 'wb') as new_model_file:
#     pickle.dump(loaded_model, new_model_file)

# print("Pickle file re-saved successfully.")