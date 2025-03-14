import streamlit as st
import re
import secrets
import string

class PasswordAnalyzer:
    @staticmethod
    def analyze_password_strength(password):
        """
        Analyze the strength of a password using multiple methods
        Returns a comprehensive strength analysis
        """
        # Basic strength analysis
        length = len(password)
        
        # Check character diversity
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_symbols = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        # Calculate strength score
        strength_score = 0
        
        # Length scoring
        if length < 6:
            strength_score += 1
        elif length < 8:
            strength_score += 2
        elif length < 12:
            strength_score += 3
        else:
            strength_score += 4
        
        # Character diversity scoring
        diversity_count = sum([has_uppercase, has_lowercase, has_digits, has_symbols])
        strength_score += diversity_count
        
        # Determine strength level
        if strength_score <= 2:
            strength_level = "Very Weak"
        elif strength_score <= 4:
            strength_level = "Weak"
        elif strength_score <= 6:
            strength_level = "Moderate"
        elif strength_score <= 8:
            strength_level = "Strong"
        else:
            strength_level = "Very Strong"
        
        return {
            'basic_strength_level': strength_level,
            'basic_strength_score': strength_score,
            'character_stats': {
                'uppercase': has_uppercase,
                'lowercase': has_lowercase,
                'digits': has_digits,
                'symbols': has_symbols,
                'length': length
            }
        }
    
    @staticmethod
    def generate_strong_password(length=12, include_uppercase=True, 
                                  include_lowercase=True, 
                                  include_digits=True, 
                                  include_symbols=True):
        """
        Generate a strong random password with customizable character sets
        """
        # Define character sets based on user preferences
        character_sets = []
        if include_uppercase:
            character_sets.append(string.ascii_uppercase)
        if include_lowercase:
            character_sets.append(string.ascii_lowercase)
        if include_digits:
            character_sets.append(string.digits)
        if include_symbols:
            character_sets.append(string.punctuation)
        
        # Ensure at least one character from each selected set
        if not character_sets:
            raise ValueError("At least one character set must be selected")
        
        # Generate password
        password = []
        for char_set in character_sets:
            password.append(secrets.choice(char_set))
        
        # Fill the rest of the password
        all_chars = ''.join(character_sets)
        password.extend(secrets.choice(all_chars) for _ in range(length - len(password)))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)

def main():
    st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔐")
    
    st.title("🔐 Professional Password Strength Analyzer")
    
    # Initialize session state for password history
    if 'password_history' not in st.session_state:
        st.session_state.password_history = []
    
    # Tabs for different functionalities
    tab1, tab2, tab3, tab4 = st.tabs([
        "Password Strength Checker", 
        "Password Generator", 
        "Password History", 
        "Advanced Options"
    ])
    
    with tab1:
        st.header("Password Strength Analysis")
        password = st.text_input("Enter your password", type="password", key="strength_input")
        
        if password:
            # Analyze password strength
            analysis = PasswordAnalyzer.analyze_password_strength(password)
            
            # Color-coded strength indicator
            strength_levels = {
                "Very Weak": "red",
                "Weak": "orange",
                "Moderate": "yellow",
                "Strong": "green",
                "Very Strong": "darkgreen"
            }
            color = strength_levels.get(analysis['basic_strength_level'], "red")
            
            # Display strength analysis
            st.markdown(f"**Strength Level:** <span style='color:{color}'>{analysis['basic_strength_level']}</span>", 
                        unsafe_allow_html=True)
            st.write(f"Basic Strength Score: {analysis['basic_strength_score']}/10")
            
            # Character diversity
            st.subheader("Character Diversity")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Uppercase", "✓" if analysis['character_stats']['uppercase'] else "✗")
            with col2:
                st.metric("Lowercase", "✓" if analysis['character_stats']['lowercase'] else "✗")
            with col3:
                st.metric("Digits", "✓" if analysis['character_stats']['digits'] else "✗")
            with col4:
                st.metric("Symbols", "✓" if analysis['character_stats']['symbols'] else "✗")
            
            # Save to password history
            if st.button("Save to History", key="save_strength"):
                st.session_state.password_history.append({
                    'password': '*' * len(password),
                    'strength': analysis['basic_strength_level']
                })
    
    with tab2:
        st.header("Strong Password Generator")
        
        # Password generation options
        col1, col2 = st.columns(2)
        with col1:
            length = st.slider("Password Length", min_value=8, max_value=64, value=12, key="length_slider")
        
        with col2:
            st.write("Include Character Types:")
            include_uppercase = st.checkbox("Uppercase", value=True, key="uppercase_check")
            include_lowercase = st.checkbox("Lowercase", value=True, key="lowercase_check")
            include_digits = st.checkbox("Digits", value=True, key="digits_check")
            include_symbols = st.checkbox("Symbols", value=True, key="symbols_check")
        
        if st.button("Generate Password", key="generate_btn"):
            try:
                generated_password = PasswordAnalyzer.generate_strong_password(
                    length=length,
                    include_uppercase=include_uppercase,
                    include_lowercase=include_lowercase,
                    include_digits=include_digits,
                    include_symbols=include_symbols
                )
                st.text_input("Generated Password", value=generated_password, type="password", key="generated_password")
                
                # Analyze generated password
                analysis = PasswordAnalyzer.analyze_password_strength(generated_password)
                st.success(f"Generated Password Strength: {analysis['basic_strength_level']}")
                
                # Option to save to history
                if st.button("Save to History", key="save_generated"):
                    st.session_state.password_history.append({
                        'password': '*' * len(generated_password),
                        'strength': analysis['basic_strength_level']
                    })
            except ValueError as e:
                st.error(str(e))
    
    with tab3:
        st.header("Password History")
        
        if not st.session_state.password_history:
            st.info("No passwords saved in the current session.")
        else:
            # Display password history
            for idx, entry in enumerate(st.session_state.password_history, 1):
                st.write(f"{idx}. Password: {entry['password']} | Strength: {entry['strength']}")
            
            # Clear history option
            if st.button("Clear History", key="clear_history"):
                st.session_state.password_history = []
                st.experimental_rerun()
    
    with tab4:
        st.header("Advanced Password Security Tips")
        
        st.subheader("Best Practices")
        tips = [
            "Use a unique password for each account",
            "Avoid using personal information in passwords",
            "Consider using a password manager",
            "Enable two-factor authentication when possible",
            "Regularly update your passwords",
            "Avoid using common password patterns"
        ]
        
        for tip in tips:
            st.write(f"- {tip}")
        
        st.subheader("Password Leak Check")
        email = st.text_input("Enter your email to check for potential breaches", key="email_breach_check")
        if st.button("Check Email", key="check_breach"):
            st.info("Note: Actual breach checking would require integration with services like HaveIBeenPwned API")

if __name__ == "__main__":
    main()
