def IA_Decision(mat, profondeur=7):
    meilleure_action = None
    alpha = -float('inf')
    beta = float('inf')
    v = -float('inf')
    
    for action in actions(mat):
        valeur_action = min_value(Result(mat, action, 1), profondeur - 1, alpha, beta, action)
        if valeur_action > v: 
            v = valeur_action
            meilleure_action = action
        alpha = max(alpha, v)
    return meilleure_action



def utility(mat, last_coup):
    COLS = 12
    ROWS = 6
    col = last_coup
    row = 0
    while row < ROWS and mat[row][col] == 0:
        row += 1
    if row >= ROWS:
        return 0   
    last_joueur = mat[row][col]
    directions = [
        [(0, 1)],                 
        [(-1, 0), (1, 0)],        
        [(-1, 1), (1, -1)], 
        [(-1, 1), (1, -1)]      
    ]
    for axes in directions:
        affile = 1
        for d_col, d_row in axes:
            c = col + d_col
            r = row + d_row
            while 0 <= c < COLS and 0 <= r < ROWS and mat[r][c] == last_joueur:
                affile += 1
                c += d_col
                r += d_row   
        if affile >= 4:
            return 100000 * last_joueur
    return 0

def Terminal_Test(grille):
    for i in range(6):
        for j in range (9) :
            if grille[i][j] == grille[i][j+1] == grille[i][j+2] == grille[i][j+3] != 0:
                return True

    for a in range(3):
        for b in range(12):
            if grille[a][b] == grille[a+1][b] == grille[a+2][b] == grille[a+3][b] != 0:
                return True

    for x in range (3) :
        for z in range (9) :
            if grille[x][z] == grille[x+1][z+1] == grille[x+2][z+2] == grille[x+3][z+3] != 0 :
                return True

    for e in range(3, 6):
        for d in range(9):
            if grille[e][d] == grille[e - 1][d + 1] == grille[e - 2][d + 2] == grille[e - 3][d + 3] != 0:
                return True

    for v in grille[0]   :
        if v == 0 :
            return False

    return True



def score(mat):
    score = 0
    bot_piece = 1
    opp_piece = -1
    COLS = 12
    ROWS = 6

    for r in range(ROWS):
        if mat[3][r] == bot_piece:
            score += 30

    def evaluer_compteurs(b_count, o_count):
        if b_count == 4:
            return 100000
        elif b_count == 3 and o_count == 0:
            return 50
        elif b_count == 2 and o_count == 0:
            return 10
        elif o_count == 3 and b_count == 0:
            return -80
        elif o_count == 4:
            return -100000
        return 0

    for r in range(ROWS):
        for c in range(COLS - 3):
            bot_count = 0
            opp_count = 0
            for i in range(4):
                val = mat[r][c+i]
                if val == bot_piece: bot_count += 1
                elif val == opp_piece: opp_count += 1
            
            pts = evaluer_compteurs(bot_count, opp_count)
            if pts == 100000: return 100000
            score += pts

    for c in range(COLS):
        for r in range(ROWS - 3):
            bot_count = 0
            opp_count = 0
            for i in range(4):
                val = mat[r+i][c]
                if val == bot_piece: bot_count += 1
                elif val == opp_piece: opp_count += 1
                
            pts = evaluer_compteurs(bot_count, opp_count)
            if pts == 100000: return 100000
            score += pts

    for c in range(COLS - 3):
        for r in range(ROWS - 3):
            bot_count = 0
            opp_count = 0
            for i in range(4):
                val = mat[r+i][c+i]
                if val == bot_piece: bot_count += 1
                elif val == opp_piece: opp_count += 1
                
            pts = evaluer_compteurs(bot_count, opp_count)
            if pts == 100000: return 100000
            score += pts

    for c in range(COLS - 3):
        for r in range(3, ROWS):
            bot_count = 0
            opp_count = 0
            for i in range(4):
                val = mat[r-i][c+i]
                if val == bot_piece: bot_count += 1
                elif val == opp_piece: opp_count += 1
                
            pts = evaluer_compteurs(bot_count, opp_count)
            if pts == 100000: return 100000
            score += pts

    return score

def Result(mat, action, joueur):
    new_mat = [ligne[:] for ligne in mat]
    for i in range(5, -1, -1):
        if new_mat[i][action] == 0:
            new_mat[i][action] = joueur
            return new_mat
    return new_mat

def max_value(board, profondeur, alpha, beta, action):
    meilleur_score = -float("inf")
    if Terminal_Test(board):
        return utility(board, action)
    if profondeur == 0:
        return score(board)
    for col in actions(board):
        new_board = Result(board, col, 1)
        score_coup = min_value(new_board, profondeur - 1, alpha, beta, col)
        if score_coup > meilleur_score:
            meilleur_score = score_coup
        if meilleur_score > alpha:
            alpha = meilleur_score
        if alpha >= beta:
            return meilleur_score
    return meilleur_score


def min_value(board, profondeur, alpha, beta, action):
    meilleur_score = float("inf")
    if Terminal_Test(board):
        return utility(board, action)
    if profondeur == 0:
        return score(board)
    for col in actions(board):
        new_board = Result(board, col, -1)
        score_coup = max_value(new_board, profondeur - 1, alpha, beta, col)
        if score_coup < meilleur_score:
            meilleur_score = score_coup
        if meilleur_score < beta:
            beta = meilleur_score
        if alpha >= beta:
            return meilleur_score
    return meilleur_score

def actions(board):
    coups = []
    ordreCol = [5, 6, 4, 7, 3, 8, 2, 9, 1, 10, 0, 11]
    for col in ordreCol:
        if board[0][col] == 0:
            coups.append(col)
    return coups


def afficher_grille(board):
    # Parcourt chaque ligne du plateau, de haut en bas
    for row in board:
        ligne_str = "|"
        for cell in row:
            if cell == 1:
                ligne_str += "X|"
            elif cell == -1:
                ligne_str += "O|"  # Tu peux mettre 'o' ou '0' selon ta préférence
            else:
                ligne_str += " |"
        print(ligne_str)
        
    # Calcule le nombre de colonnes en regardant la taille de la première ligne
    nb_cols = len(board[0])
    
    # Affiche la ligne de tirets (2 tirets par case + 1 pour fermer)
    print("-" * (nb_cols * 2 + 1))
    
    # Affiche la ligne des indices
    indices_str = "|"
    for i in range(nb_cols):
        # i % 10 permet d'afficher 0 pour 10, 1 pour 11, etc., pour garder une seule largeur
        indices_str += f"{i % 10}|"
        
    print(indices_str)
