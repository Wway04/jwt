const generateTokens = user => {
  const accessToken = jwt.sign(
    {id: user.id, email: user.email},
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  const refreshToken = jwt.sign(
    {id: user.id, email: user.email},
    process.env.JWT_REFRESH_REFRESH,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
}